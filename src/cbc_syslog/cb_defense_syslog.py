import socket
import ssl
import sys
import argparse
import ConfigParser
import requests
from jinja2 import Template
import os
import json
import logging
import logging.handlers
import traceback
import hashlib
import fcntl
import audit_log as al
import notifications as n

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

policy_action_severity = 4

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

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


def delete_stored_data(hash, back_up_dir):
    try:
        os.remove(back_up_dir + hash)
    except:
        logger.error(traceback.format_exc())



def send_stored_data(back_up_dir):
    logger.info("Number of files in store forward: {0}".format(len(os.listdir(back_up_dir))))
    for file_name in os.listdir(back_up_dir):
        file_data = open(back_up_dir + file_name, 'rb').read()
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
            delete_stored_data(file_name, back_up_dir)

def send_syslog_tls(server_url, port, data, output_type, output_format, ssl_verify=True):
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
            resp = requests.post(headers=output_params['http_headers'],
                                 url=server_url,
                                 data=data.encode("utf-8"),
                                 verify=ssl_verify)
            logger.info(resp)
        except Exception as e:
            logger.error(traceback.format_exc())
            retval = False

    return retval

def verify_config_parse_servers():
    """
    Validate configuration parameters
    """
    global policy_action_severity

    output_params = {}
    output_params['https_ssl_verify'] = True
    server_list = []

    #
    # Verify output_format
    #

    if not config.has_option('general', 'output_format'):
        logger.error('output_format of json or cef was not specified')
        logger.warn('Setting output format to CEF')
        config.set('general', 'output_format', 'cef')

    output_format = config.get('general', 'output_format').lower()

    if not output_format == 'cef' and not output_format == 'json' and output_format == 'leef':
        logger.error('invalid output_format type was specified')
        logger.error('Must specify JSON, CEF , or LEEF output format')
        logger.warn('Setting output format to CEF')
        output_format = 'cef'

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

    back_up_dir = config.get('general', 'back_up_dir')

    output_params['back_up_dir'] = back_up_dir
    output_params['output_type'] = output_type
    output_params['output_format'] = output_format
    output_params['https_ssl_verify'] = True

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
        try:
            output_params['output_host'] = config.get('general', 'http_out')
            output_params['output_port'] = None
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("http_out must be of format http(s)://<ip>:<port>")
            sys.exit(-1)
        #
        # User has specified http.
        #
        if not config.has_option('general', 'http_out'):
            logger.error('http_out parameter is required for http output_type')
            logger.error('Example: https://server.company.com/endpoint')
            sys.exit(-1)

        output_params['output_host'] = config.get('general', 'http_out')

        output_params['http_headers'] = {'content-type': 'application/json'}
        if config.has_option('general', 'http_headers'):
            try:
                output_params['http_headers'] = json.loads(config.get('general', 'http_headers').strip())
            except Exception as e:
                logger.error(str(e))
                logger.error("Invalid http_headers: unable to parse JSON")
                sys.exit(-1)

        if config.has_option('general', 'https_ssl_verify'):
            output_params['https_ssl_verify'] = bool(config.get('general', 'https_ssl_verify'))

    output_params['requests_ca_cert'] = "/usr/share/cb/integrations/cb-defense-syslog/cacert.pem"
    if config.has_option('general', 'requests_ca_cert'):
        output_params['requests_ca_cert'] = config.get('general', 'requests_ca_cert')

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
        if config.has_option(section, 'server_url'):
            if not config.get(section, 'server_url').startswith('http'):
                logger.error('Stanza {0} server_url entry does not start with http or https'.format(section))
                logger.error('Example: https://server.yourcompany.com')
                sys.exit(-1)

            server['server_url'] = config.get(section, 'server_url')

        if config.has_option(section, 'siem_connector_id') and config.has_option(section, 'siem_api_key'):
            server['siem_connector_id'] = config.get(section, 'siem_connector_id')
            server['siem_api_key'] = config.get(section, 'siem_api_key')

        if config.has_option(section, 'api_connector_id') and config.has_option(section, 'api_key'):
            server['api_connector_id'] = config.get(section, 'api_connector_id')
            server['api_key'] = config.get(section, 'api_key')

        if not 'server_url' in server or not 'api_connector_id' in server or not 'api_key' in server:
            logger.error("The {0} section does not contain the necessary CB Defense parameters".format(section))
            sys.exit(-1)

        server['source'] = section
        server_list.append(server)

    return output_params, server_list

def get_response(server):
    notification_response = n.notification_server_request(server.get('server_url'),
                                                          server.get('siem_api_key'),
                                                          server.get('siem_connector_id'),
                                                          True)

    audit_response = al.get_audit_logs(server.get('server_url'), server.get('api_key'), server.get('api_connector_id'),
                                       server.get('https_ssl_verify'))
    if notification_response is None:
        logger.warn(
            "Received unexpected (or no) response from Cb Defense Server {0}. Proceeding to next connector.".format(
                server.get('server_url')))
        notifications_response = None
    else:
        notifications_response = json.loads(notification_response.content)

    if audit_response is None:
        logger.info("Retrieval of Audit Logs Failed")
        audit_response=None
    else:
        audit_response = json.loads(audit_response.content)

    return notifications_response, audit_response

def parse_notifications(server, notifications_response, audit_response):
    source = server.get('source', '')
    accepted_formats=['json', 'leef', 'cef']
    notifications_log = None
    audit_log = None

    if config.get('general', 'output_format') not in accepted_formats:
        return None

    if notifications_response is not None:
        if config.get('general', 'output_format').lower() == 'json':
            notifications_log = n.parse_response_json_psc(notifications_response, source, get_unicode_string)
        elif config.get('general', 'output_format').lower() == 'cef':
            notifications_log = n.parse_response_cef_psc(notifications_response, source, get_unicode_string)
        else:
            notifications_log = n.parse_response_leef_psc(notifications_response, source, get_unicode_string)

    if audit_response is not None:
        if config.get('general', 'output_format').lower() == 'json':
            audit_log = al.parse_response_json(audit_response, source, get_unicode_string)
        elif config.get('general', 'output_format').lower() == 'cef':
            audit_log = al.parse_response_cef(audit_response, source, get_unicode_string)
        else:
            audit_log = al.parse_response_leef(audit_response, source, get_unicode_string)

    return notifications_log, audit_log

def send_data_syslog(log_messages, back_up_dir):

    def send_data(data):

        byte_data = data.encode("utf-8")
        hash = hashlib.sha256(byte_data).hexdigest()

        try:
            with open(back_up_dir + hash, 'wb') as f:
                f.write(byte_data)
        except:
            logger.error(traceback.format_exc())
            return None

        if not hash:
            logger.error("We were unable to store notifications.")

        if send_syslog_tls(output_params['output_host'],
                           output_params['output_port'],
                           data,
                           output_params['output_type'],
                           output_params['output_format'],
                           output_params['https_ssl_verify']):
            #
            # If successful send, then we just delete the stored version
            #
            delete_stored_data(hash, back_up_dir)

    if log_messages is None:
        logger.info("There are no messages to forward to host")
    elif output_params['output_port']:
        logger.info("Sending {0} messages to {1}:{2}".format(len(log_messages),
                                                             output_params['output_host'],
                                                             output_params['output_port']))
    else:
        logger.info("Sending {0} messages to {1}".format(len(log_messages),
                                                         output_params['output_host']))

    if log_messages is not None:
        #
        # finally send the messages
        #
        for log in log_messages:

            final_data = ''

            output_format = config.get('general', 'output_format').lower()

            if output_format == 'json':
                final_data = json.dumps(log) + '\n'
            elif output_format == 'cef':
                template = Template(config.get('general', 'template'))
                final_data = template.render(log) + '\n'
            elif output_format == 'leef':
                final_data = log + "\n"

            send_data(final_data)

def main():

    global output_params

    config = parse_config()
    if not config:
        logger.error("Error parsing config file")
        sys.exit(-1)

    # verify the config file and get the Cb Defense Server list
    output_params, server_list = verify_config_parse_servers()

    if os.path.isfile(output_params['requests_ca_cert']):
        os.environ["REQUESTS_CA_BUNDLE"] = output_params['requests_ca_cert']

    # # Store Forward.  Attempt to send messages that have been saved but we were unable to reach the destination
    back_up_dir = output_params['back_up_dir']
    send_stored_data(back_up_dir)

    # Error or not, there is nothing to do
    if len(server_list) == 0:
        logger.info("no configured Cb Defense Servers")
        sys.exit(-1)

    logger.info("Found {0} Cb Defense Servers in config file".format(len(server_list)))

    # Iterate through our Cb Defense Server list
    for server in server_list:
        logger.info("Handling notifications for {0}".format(server.get('server_url')))

        notifications_response, audit_response = get_response(server)
        notification_log, audit_log = parse_notifications(server, notifications_response, audit_response)
        logger.info("Sending Notifications")
        send_data_syslog(notification_log, back_up_dir)
        logger.info("Done Sending Notifications")
        logger.info("Sending Audit Logs")
        send_data_syslog(audit_log, back_up_dir)
        logger.info("Done Sending Audit Logs")



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

    logger.info("CB Defense Syslog 2.0")

    try:
        pid_file = 'root/usr/share/cb/integrations/cb-defense-syslog.pid'
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

