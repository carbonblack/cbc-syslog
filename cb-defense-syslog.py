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


def get_audit_logs(url, api_key_query, connector_id_query, ssl_verify):
    headers = {'X-Auth-Token': "{0}/{1}".format(api_key_query, connector_id_query)}
    try:
        response = requests.get("{0}/integrationServices/v3/auditlogs".format(url),
                                headers=headers,
                                timeout=15)

        if response.status_code != 200:
            logger.error("Could not retrieve audit logs: {0}".format(response.status_code))
            return False

        notifications = response.json()
    except Exception as e:
        logger.error("Exception {0} when retrieving audit logs".format(str(e)), exc_info=True)
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


def cb_defense_server_request(url, api_key, connector_id, ssl_verify):
    logger.info("Attempting to connect to url: " + url)

    headers = {'X-Auth-Token': "{0}/{1}".format(api_key, connector_id)}
    try:
        response = requests.get(url + '/integrationServices/v3/notification', headers=headers, timeout=15,
                                verify=ssl_verify)
        logger.info(response)
    except Exception as e:
        logging.error(e, exc_info=True)
        return None
    else:
        return response


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
        #
        # Store notifications just in case sending fails
        #
        if send_syslog_tls(output_params['output_host'],
                           output_params['output_port'],
                           file_data,
                           output_params['output_type']):
            #
            # If the sending was successful, delete the stored data
            #
            delete_store_notification(file_name)


def store_notifications(data):
    #
    # We hash the data to generate a unique filename
    #
    hash = hashlib.sha256(data).hexdigest()

    try:
        with open(store_forwarder_dir + hash, 'wb') as f:
            f.write(data)
    except:
        logger.error(traceback.format_exc())
        return None

    return hash


def send_syslog_tls(server_url, port, data, output_type):
    retval = True
    client_socket = None
    if output_type == 'tcp+tls':
        unsecured_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if config.getboolean('tls', 'tls_verify'):
                cert_reqs = ssl.CERT_REQUIRED
            else:
                cert_reqs = ssl.CERT_NONE

            client_socket = ssl.wrap_socket(unsecured_client_socket,
                                            ca_certs=config.get('tls', 'ca_cert'),
                                            cert_reqs=cert_reqs,
                                            ssl_version=ssl.PROTOCOL_TLSv1)

            client_socket.connect((server_url, port))
            client_socket.send(data)
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
            client_socket.send(data)
        except Exception as e:
            logger.error(traceback.format_exc())
            retval = False
        finally:
            if client_socket:
                client_socket.close()

    elif output_type == 'udp':
        unsecured_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            unsecured_client_socket.sendto(data, (server_url, port))
        except Exception as e:
            logger.error(traceback.format_exc())
            retval = False
        finally:
            if unsecured_client_socket:
                unsecured_client_socket.close()

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

    return response[u'notifications']


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
                seconds = str(note['eventTime'])[:-3]
                name = str(note['threatInfo']['summary'])
                severity = str(note['threatInfo']['score'])
                device_name = str(note['deviceInfo']['deviceName'])
                user_name = str(note['deviceInfo']['email'])
                device_ip = str(note['deviceInfo']['internalIpAddress'])
                link = str(note['url'])
                tid = str(note['threatInfo']['incidentId'])
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
                seconds = str(note['eventTime'])[:-3]
                timestamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
                device_name = str(note['deviceInfo']['deviceName'])
                user_name = str(note['deviceInfo']['email'])
                device_ip = str(note['deviceInfo']['internalIpAddress'])
                sha256 = str(note['policyAction']['sha256Hash'])
                action = str(note['policyAction']['action'])
                app_name = str(note['policyAction']['applicationName'])
                link = str(note['url'])
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
            not config.get('general', 'output_foramt').lower() == 'json':
        logger.error('invalid output_format type was specified')
        logger.error('Must specify JSON or CEF output format')
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
    if output_type not in ['tcp', 'udp', 'tcp+tls']:
        logger.error('output_type is invalid.  Must be tcp, udp, or tcp+tls')
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
        try:
            config.getboolean('tls', 'tls_verify')
        except ValueError as e:
            logger.error(traceback.format_exc())
            logger.error("tls_verify must be either true or false")
            sys.exit(-1)
        output_params['output_host'] = config.get('general', 'tcp_out').strip().split(":")[0]
        output_params['output_port'] = int(config.get('general', 'tcp_out').strip().split(':')[1])

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

    return output_params, server_list


def main():
    global output_params

    cacert_pem_path = "/usr/share/cb/integrations/cb-defense-syslog/cacert.pem"
    if os.path.isfile(cacert_pem_path):
        os.environ["REQUESTS_CA_BUNDLE"] = cacert_pem_path

    config = parse_config()
    if not config:
        logger.error("Error parsing config file")
        sys.exit(-1)

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

                if config.get('general', 'output_format').lower() == 'json':
                    final_data = json.dumps(log) + '\n'

                if config.get('general', 'output_format').lower() == 'cef':
                    template = Template(config.get('general', 'template'))
                    final_data = template.render(log) + '\n'

                #
                # Store notifications just in case sending fails
                #
                hash = store_notifications(final_data)
                if not hash:
                    logger.error("We were unable to store notifications.")

                if send_syslog_tls(output_params['output_host'],
                                   output_params['output_port'],
                                   final_data,
                                   output_params['output_type']):
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

    global args

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

    main()
