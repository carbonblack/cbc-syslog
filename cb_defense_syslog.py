import socket
import ssl
import sys
import argparse
import ConfigParser
import requests
from jinja2 import Template
import os
import json
import time
import logging
import logging.handlers
import traceback
import hashlib
import fcntl

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

store_forwarder_dir = '/usr/share/cb/integrations/cb-defense-syslog/store/'
policy_action_severity = 4

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str


def get_audit_logs(url, api_key_query, connector_id_query, ssl_verify, proxies=None):
    headers = {'X-Auth-Token': "{0}/{1}".format(api_key_query, connector_id_query)}
    try:
        response = requests.get("{0}/integrationServices/v3/auditlogs".format(url),
                                headers=headers,
                                timeout=15, proxies=proxies)

        if response.status_code != 200:
            logger.error("Could not retrieve audit logs: {0}".format(response.status_code))
            return False

        notifications = response.json()
    except Exception as e:
        logger.error("Exception {0} when retrieving audit logs".format(get_unicode_string(e)), exc_info=True)
        return None

    if notifications.get("success", False) != True:
        logger.error("Unsuccessful HTTP response retrieving audit logs: {0}"
                     .format(notifications.get("message")))
        return False

    notifications = notifications.get("notifications", [])
    if not notifications:
        logger.info("No audit logs available")
        return False

    return notifications


def parse_cb_defense_response_leef(response, source):
    # LEEF: 2.0 | Vendor | Product | Version | EventID | xa6 |
    version = 'LEEF:2.0'
    vendor = 'CarbonBlack'
    product = 'CbDefense'
    dev_version = '0.1'
    hex_sep = "x09"
    splitDomain = True

    leef_header = '|'.join([version, vendor, product, dev_version])
    log_messages = []

    success = False

    if response:
        response = response.json()
        success = response.get("success", False)

    if not success:
        return log_messages

    if success:

        if len(response['notifications']) < 1:
            logger.info('successfully connected, no alerts at this time')
            return None
        for note in response['notifications']:
            indicators = []
            current_notification_leef_header = leef_header
            eventId = get_unicode_string(note.get('eventId'))
            kvpairs = {"eventId": eventId}
            devTime = note.get("eventTime", 0)
            devTime = time.strftime('%b-%d-%Y %H:%M:%S GMT', time.gmtime(devTime / 1000))
            devTimeFormat = "MMM dd yyyy HH:mm:ss z"
            url = note.get("url", "noUrlProvided")
            ruleName = note.get("ruleName", "noRuleName")
            kvpairs.update({"devTime": devTime, "devTimeFormat": devTimeFormat, "url": url, "ruleName": ruleName})
            if note.get('type', 'noType') == 'THREAT' or note.get('threatInfo', False):
                current_notification_leef_header += "|{0}|{1}|".format("THREAT", hex_sep)
                cat = "THREAT"
                indicators = note['threatInfo'].get('indicators', [])
                kvpairs.update(note.get("deviceInfo", {}))
                kvpairs.update({"incidentId": note['threatInfo'].get("incidentId", "noIncidentId")})
                signature = 'Active_Threat'
                summary = get_unicode_string(note['threatInfo'].get('summary', ""))
                sev = get_unicode_string(note['threatInfo']['score'])
                device_name = get_unicode_string(note['deviceInfo']['deviceName'])
                email = get_unicode_string(note['deviceInfo']['email'])
                src = get_unicode_string(note['deviceInfo'].get('internalIpAddress', "0.0.0.0"))
                kvpairs.update({"cat": cat, "url": url, "type": "THREAT", "signature": signature, "sev": sev,
                                "resource": device_name, "email": email, "src": src, "identSrc": src, "dst": src,
                                "identHostName": device_name, "summary": summary})

            elif note.get('type', "noType") == 'POLICY_ACTION' or note.get("policyAction", False):
                severity = 1
                summary = get_unicode_string(note['policyAction'].get('summary', ''))
                device_name = get_unicode_string(note['deviceInfo']['deviceName'])
                email = get_unicode_string(note['deviceInfo']['email'])
                src = get_unicode_string(note['deviceInfo'].get('internalIpAddress', "0.0.0.0"))
                sha256 = get_unicode_string(note['policyAction']['sha256Hash'])
                action = note.get('policyAction', {}).get('action', None)
                current_notification_leef_header += "|" + (
                    get_unicode_string(action) if action else "POLICY_ACTION") + "|" + hex_sep + "|"
                app_name = get_unicode_string(note['policyAction']['applicationName'])
                reputation = get_unicode_string(note['policyAction'].get('reputation', ""))
                url = get_unicode_string(note['url'])
                kvpairs.update({"cat": "POLICY_ACTION", "sev": severity, "type": "POLICY_ACTION", "action": action,
                                "reputation": reputation, "resource": device_name, "email": email, "src": src,
                                "dst": src, "identSrc": src, "identHostName": device_name, "summary": summary,
                                "sha256Hash": sha256, "applicationName": app_name, "url": url})

            else:
                continue

            log_messages.append(
                current_notification_leef_header + "\t".join(["{0}={1}".format(k, kvpairs[k]) for k in kvpairs]))

            for indicator in indicators:
                indicator_name = indicator['indicatorName']
                indicator_header = leef_header + "|{0}|{1}|".format(indicator_name, hex_sep)
                indicator_dict = indicator_header + "\t".join(
                    ["{0}={1}".format(k, kvpairs[k]) for k in kvpairs]) + "\t" + "\t".join(
                    ["{0}={1}".format(k, indicator[k]) for k in indicator])
                log_messages.append(indicator_dict)

    return log_messages


def cb_defense_server_request(url, api_key, connector_id, ssl_verify, proxies=None):
    logger.info("Attempting to connect to url: " + url)

    headers = {'X-Auth-Token': "{0}/{1}".format(api_key, connector_id)}
    try:
        response = requests.get(url + '/integrationServices/v3/notification', headers=headers, timeout=15,
                                verify=ssl_verify, proxies=proxies)
        logger.info(response)
    except Exception as e:
        logging.error(e, exc_info=True)
        return None
    else:
        return response


def gather_notification_context(url, notification_id, api_key_query, connector_id_query, ssl_verify, proxies=None):
    try:
        response = requests.get("{0}/integrationServices/v3/alert/{1}".format(url,
                                                                              notification_id),
                                headers={"X-Auth-Token": "{0}/{1}".format(api_key_query,
                                                                          connector_id_query)})
        if response.status_code != 200:
            logger.error("Could not retrieve context for id {0}: {1}".format(notification_id,
                                                                             response.status_code))
            return None

        return response.json()
    except Exception as e:
        logger.exception("Could not retrieve notification context for org id {1}: {2}".format(
            notification_id,
            str(e)))
        return None


def parse_config():
    """
    parse the config file into globals
    :return:
    """
    global config
    try:
        config = ConfigParser.ConfigParser()
        config.readfp(open(args.config_file))
    except Exception as e:
        logging.error(e, exc_info=True)
        return None
    else:
        return config


def delete_store_notification(hash):
    try:
        os.remove(store_forwarder_dir + hash)
    except:
        logger.error(traceback.format_exc())


def send_store_notifications():
    logger.info("Number of files in store forward: {0}".format(len(os.listdir(store_forwarder_dir))))
    for file_name in os.listdir(store_forwarder_dir):
        file_data = open(store_forwarder_dir + file_name, 'rb').read()
        file_data = file_data.decode("utf-8")
        #
        # Store notifications just in case sending fails
        #
        if send_syslog_tls(output_params['output_host'],
                           output_params['output_port'],
                           file_data,
                           output_params['output_type'],
                           output_params['output_format']):
            #
            # If the sending was successful, delete the stored data
            #
            delete_store_notification(file_name)


def store_notifications(data):
    #
    # We hash the data to generate a unique filename
    #
    byte_data = data.encode("utf-8")
    hash = hashlib.sha256(byte_data).hexdigest()

    try:
        with open(store_forwarder_dir + hash, 'wb') as f:
            f.write(byte_data)
    except:
        logger.error(traceback.format_exc())
        return None

    return hash


def send_syslog_tls(server_url, port, data, output_type, output_format):
    retval = True
    client_socket = None
    if output_type == 'tcp+tls':
        unsecured_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=config.get('tls', 'ca_cert'))
            if config.has_option('tls', 'cert'):
                passwd = None
                if config.has_option('tls', 'key_password'):
                    passwd = config.get('tls', 'key_password')
                context.load_cert_chain(config.get('tls', 'cert'), keyfile=config.get('tls', 'key'), password=passwd)

            if not config.getboolean('tls', 'tls_verify'):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            client_socket = context.wrap_socket(unsecured_client_socket, server_hostname=server_url)

            client_socket.connect((server_url, port))
            client_socket.send(data.encode("utf-8"))
        except Exception as e:
            logger.error(traceback.format_exc())
            retval = False
        finally:
            if client_socket:
                client_socket.close()

    elif output_type == 'tcp':
        unsecured_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket = unsecured_client_socket
        try:
            client_socket.connect((server_url, port))
            client_socket.send(data.encode("utf-8"))
        except Exception as e:
            logger.error(traceback.format_exc())
            retval = False
        finally:
            if client_socket:
                client_socket.close()

    elif output_type == 'udp':
        unsecured_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            unsecured_client_socket.sendto(data.encode("utf-8"), (server_url, port))
        except Exception as e:
            logger.error(traceback.format_exc())
            retval = False
        finally:
            if unsecured_client_socket:
                unsecured_client_socket.close()

    elif output_type == 'http':
        try:
            if output_format == 'json':
                headers = {'content-type': 'application/json'}
                requests.post(headers=headers, url=server_url, data=data.encode("utf-8"))
            else:
                requests.post(url=server_url, data=data.encode("utf-8"))
        except Exception as e:
            logger.error(traceback.format_exc())
            retval = False

    return retval


def parse_cb_defense_response_json(response, source):
    if u'success' not in response:
        return None

    if response[u'success']:
        if len(response[u'notifications']) < 1:
            logger.info('successfully connected, no alerts at this time')
            return None

        for notification in response[u'notifications']:
            if 'type' not in notification:
                notification['type'] = 'THREAT'
            notification['source'] = source

    return response['notifications']


def parse_cb_defense_response_cef(response, source):
    version = 'CEF:0'
    vendor = 'CarbonBlack'
    product = 'CbDefense_Syslog_Connector'
    dev_version = '2.0'
    splitDomain = True

    log_messages = []

    if u'success' not in response:
        return log_messages

    if response[u'success']:

        if len(response[u'notifications']) < 1:
            logger.info('successfully connected, no alerts at this time')
            return None

        for note in response[u'notifications']:
            if 'type' not in note:
                note['type'] = 'THREAT'

            if note['type'] == 'THREAT':
                signature = 'Active_Threat'
                seconds = get_unicode_string(note['eventTime'])[:-3]
                name = get_unicode_string(note['threatInfo']['summary'])
                severity = get_unicode_string(note['threatInfo']['score'])
                device_name = get_unicode_string(note['deviceInfo']['deviceName'])
                user_name = get_unicode_string(note['deviceInfo']['email'])
                device_ip = get_unicode_string(note['deviceInfo']['internalIpAddress'])
                link = get_unicode_string(note['url'])
                tid = get_unicode_string(note['threatInfo']['incidentId'])
                timestamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
                extension = ''
                extension += 'rt="' + timestamp + '"'

                if '\\' in device_name and splitDomain:
                    (domain_name, device) = device_name.split('\\')
                    extension += ' sntdom=' + domain_name
                    extension += ' dvchost=' + device
                else:
                    extension += ' dvchost=' + device_name

                if '\\' in user_name and splitDomain:
                    (domain_name, user) = user_name.split('\\')
                    extension += ' duser=' + user
                else:
                    extension += ' duser=' + user_name

                extension += ' dvc=' + device_ip
                extension += ' cs3Label="Link"'
                extension += ' cs3="' + link + '"'
                extension += ' cs4Label="Threat_ID"'
                extension += ' cs4="' + tid + '"'
                extension += ' act=Alert'

            elif note['type'] == 'POLICY_ACTION':
                signature = 'Policy_Action'
                name = 'Confer Sensor Policy Action'
                severity = policy_action_severity
                seconds = get_unicode_string(note['eventTime'])[:-3]
                timestamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
                device_name = get_unicode_string(note['deviceInfo']['deviceName'])
                user_name = get_unicode_string(note['deviceInfo']['email'])
                device_ip = get_unicode_string(note['deviceInfo']['internalIpAddress'])
                sha256 = get_unicode_string(note['policyAction']['sha256Hash'])
                action = get_unicode_string(note['policyAction']['action'])
                app_name = get_unicode_string(note['policyAction']['applicationName'])
                link = get_unicode_string(note['url'])
                extension = ''
                extension += 'rt="' + timestamp + '"'
                if '\\' in device_name and splitDomain == True:
                    (domain_name, device) = device_name.split('\\')
                    extension += ' sntdom=' + domain_name
                    extension += ' dvchost=' + device
                else:
                    extension += ' dvchost=' + device_name

                if '\\' in user_name and splitDomain == True:
                    (domain_name, user) = user_name.split('\\')
                    extension += ' duser=' + user
                else:
                    extension += ' duser=' + user_name

                extension += 'rt="' + timestamp + '"'
                extension += ' dvc=' + device_ip
                extension += ' cs3Label="Link"'
                extension += ' cs3="' + link + '"'
                extension += ' act=' + action
                extension += ' hash=' + sha256
                extension += ' deviceprocessname=' + app_name

            else:
                continue

            log_messages.append({'version': version,
                                 'vendor': vendor,
                                 'product': product,
                                 'dev_version': dev_version,
                                 'signature': signature,
                                 'name': name,
                                 'severity': severity,
                                 'extension': extension,
                                 'source': source})
    return log_messages


def verify_config_parse_servers():
    """
    Validate configuration parameters
    """
    global policy_action_severity

    output_params = {}
    server_list = []

    #
    # Verify output_format
    #

    if not config.has_option('general', 'output_format'):
        logger.error('output_format of json or cef was not specified')
        logger.warn('Setting output format to CEF')
        config.set('general', 'output_format', 'cef')

    elif not config.get('general', 'output_format').lower() == 'cef' and \
            not config.get('general', 'output_format').lower() == 'json' \
            and not config.get('general', 'output_format').lower() == 'leef':
        logger.error('invalid output_format type was specified')
        logger.error('Must specify JSON, CEF , or LEEF output format')
        logger.warn('Setting output format to CEF')
        config.set('general', 'output_format', 'cef')

    if not config.has_option('general', 'template'):
        logger.error('A template is required in the general stanza')
        sys.exit(-1)

    if config.has_option('general', 'policy_action_severity'):
        policy_action_severity = config.get('general', 'policy_action_severity')

    if not config.has_option('general', 'output_type'):
        logger.error('An output_type is required in the general stanza')
        sys.exit(-1)

    output_type = config.get('general', 'output_type')
    if output_type not in ['tcp', 'udp', 'tcp+tls', 'http']:
        logger.error('output_type is invalid.  Must be tcp, udp, http or tcp+tls')
        sys.exit(-1)

    if output_type == 'tcp':
        #
        # User has specified tcp.  So no TLS.
        #
        if not config.has_option('general', 'tcp_out'):
            logger.error('tcp_out parameter is required for tcp output_type')
            sys.exit(-1)

        try:
            output_params['output_host'] = config.get('general', 'tcp_out').strip().split(":")[0]
            output_params['output_port'] = int(config.get('general', 'tcp_out').strip().split(':')[1])
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("tcp_out must be of format <ip>:<port>")
            sys.exit(-1)
    elif output_type == 'udp':

        #
        # User specified udp out
        #
        if not config.has_option('general', 'udp_out'):
            logger.error('udpout parameter is required for udp output_type')
            sys.exit(-1)
        try:
            output_params['output_host'] = config.get('general', 'udp_out').strip().split(":")[0]
            output_params['output_port'] = int(config.get('general', 'udp_out').strip().split(':')[1])
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("udp_out must be of format <ip>:<port>")
            sys.exit(-1)
    elif output_type == 'tcp+tls':

        #
        # User specified TLS tcp
        #
        if not config.has_option('tls', 'tls_verify'):
            logger.error("Must specify tls_verify in config file")
            sys.exit(-1)
        if not config.has_option('tls', 'ca_cert'):
            logger.error("Must specify ca_cert file path in the general stanza")
            sys.exit(-1)
        if config.has_option('tls', 'cert') != config.has_option('tls', 'key'):
            logger.error("You cannot specify a TLS cert without specifying a TLS key")
            sys.exit(-1)
        try:
            config.getboolean('tls', 'tls_verify')
        except ValueError as e:
            logger.error(traceback.format_exc())
            logger.error("tls_verify must be either true or false")
            sys.exit(-1)
        output_params['output_host'] = config.get('general', 'tcp_out').strip().split(":")[0]
        output_params['output_port'] = int(config.get('general', 'tcp_out').strip().split(':')[1])

    elif output_type == 'http':
        #
        # User has specified http.
        #
        if not config.has_option('general', 'http_out'):
            logger.error('http_out parameter is required for http output_type')
            logger.error('Example: https://server.company.com/endpoint')
            sys.exit(-1)

        output_params['output_host'] = config.get('general', 'http_out')
        output_params['output_port'] = 0
    #
    # Parse out multiple servers
    #
    for section in config.sections():
        server = {}
        if section == 'general' or section == 'tls':
            #
            # ignore the general section
            #
            continue
        if config.has_option(section, 'server_url') and \
                config.has_option(section, 'connector_id') and \
                config.has_option(section, 'api_key'):

            if not config.get(section, 'server_url').startswith('http'):
                logger.error('Stanza {0} server_url entry does not start with http or https'.format(section))
                logger.error('Example: https://server.yourcompany.com')
                sys.exit(-1)

            server['server_url'] = config.get(section, 'server_url')

            server['connector_id'] = config.get(section, 'connector_id')
            server['api_key'] = config.get(section, 'api_key')
            server['source'] = section
            server_list.append(server)
        else:
            logger.error("The {0} section does not contain the necessary arguments".format(section))
            sys.exit(-1)

    output_params['output_type'] = config.get('general', 'output_type')
    output_params['output_format'] = config.get('general', 'output_format')

    return output_params, server_list


def main():
    global output_params

    config = parse_config()
    if not config:
        logger.error("Error parsing config file")
        sys.exit(-1)

    cacert_pem_path = "/usr/share/cb/integrations/cb-defense-syslog/cacert.pem"
    if config.has_option("general", "requests_ca_path"):
        cacert_pem_path = config.get("general", "requests_ca_path")
    if os.path.isfile(cacert_pem_path):
        os.environ["REQUESTS_CA_BUNDLE"] = cacert_pem_path

    #
    # verify the config file and get the Cb Defense Server list
    #
    output_params, server_list = verify_config_parse_servers()

    #
    # Store Forward.  Attempt to send messages that have been saved but we were unable to reach the destination
    #
    send_store_notifications()

    #
    # Error or not, there is nothing to do
    #
    if len(server_list) == 0:
        logger.info("no configured Cb Defense Servers")
        sys.exit(-1)

    logger.info("Found {0} Cb Defense Servers in config file".format(len(server_list)))
    #
    # Iterate through our Cb Defense Server list
    #
    for server in server_list:
        logger.info("Handling notifications for {0}".format(server.get('server_url')))

        response = cb_defense_server_request(server.get('server_url'),
                                             server.get('api_key'),
                                             server.get('connector_id'),
                                             True)

        if not response:
            logger.warn(
                "Received unexpected (or no) response from Cb Defense Server {0}. Proceeding to next connector.".format(
                    server.get('server_url')))
            continue

        #
        # perform fixups
        #
        # logger.debug(response.content)
        json_response = json.loads(response.content)

        #
        # parse the Cb Defense Response and get a list of log messages to send to tcp_tls_host:tcp_tls_port
        #
        if config.get('general', 'output_format').lower() == 'json':
            log_messages = parse_cb_defense_response_json(json_response, server.get('source', ''))
        elif config.get('general', 'output_format').lower() == 'cef':
            log_messages = parse_cb_defense_response_cef(json_response, server.get('source', ''))
        elif config.get('general', 'output_format').lower() == 'leef':
            log_messages = parse_cb_defense_response_leef(json_response, server.get('source', ''))
        else:
            log_messages = None

        if not log_messages:
            logger.info("There are no messages to forward to host")
        else:
            logger.info("Sending {0} messages to {1}:{2}".format(len(log_messages),
                                                                 output_params['output_host'],
                                                                 output_params['output_port']))

            #
            # finally send the messages
            #
            for log in log_messages:

                output_format = config.get('general', 'output_format').lower()

                if output_format == 'json':
                    final_data = json.dumps(log) + '\n'

                elif output_format == 'cef':
                    template = Template(config.get('general', 'template'))
                    final_data = template.render(log) + '\n'
                elif output_format == 'leef':
                    final_data = log + "\n"

                #
                # Store notifications just in case sending fails
                #
                hash = store_notifications(final_data)
                if not hash:
                    logger.error("We were unable to store notifications.")

                if send_syslog_tls(output_params['output_host'],
                                   output_params['output_port'],
                                   final_data,
                                   output_params['output_type'],
                                   output_params['output_format']):
                    #
                    # If successful send, then we just delete the stored version
                    #
                    if hash:
                        delete_store_notification(hash)
    logger.info("Done Sending Notifications")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config-file', '-c', help="Absolute path to configuration file")
    parser.add_argument('--log-file', '-l', help="Log file location")

    args = parser.parse_args()
    if not args.config_file:
        logger.error("a config file must be supplied")
        sys.exit(-1)

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
        syslog_handler.setFormatter(formatter)

        logger.addHandler(syslog_handler)

    try:
        pid_file = '/usr/share/cb/integrations/cb-defense-syslog.pid'
        fp = open(pid_file, 'w')
        try:
            fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            logger.error("An instance of cb defense syslog connector is already running")
            # another instance is running
            sys.exit(0)
        main()
    except Exception as e:
        logger.error(e, exc_info=True)
        sys.exit(-1)
