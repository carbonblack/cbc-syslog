import socket
import ssl
import sys
import argparse
import ConfigParser
import requests
from jinja2 import Template
import re
import json
import time
import logging
import logging.handlers

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(formatter)

logger.addHandler(syslog_handler)


def cb_defense_server_request(url, api_key, connector_id, ssl_verify):

    logger.info("Attempting to connect to url: ", url)

    #
    # First we need to create a session
    #
    session_data = {'apiKey': api_key, 'connectorId': connector_id}
    try:
        response = requests.post(url + '/integrationServices/v2/session', json=session_data, timeout=15, verify=False)
        logger.info(response)
    except Exception as e:
        logging.error(e, exc_info=True)
        return None

    json_response = response.json()
    #
    # TODO got 'error':'forbidden' handle this error
    #
    notification_data = {'apiKey': api_key, 'sessionId': str(json_response[u'sessionId'])}

    #
    # Now we perform the request
    #
    try:
        response = requests.post(url + '/integrationServices/v2/notification', json=notification_data, timeout=15, verify=False)
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


def fix_response(data):
    data = data.replace('None,', 'null,')
    data = re.sub(r"ime': (\d+)L", r"ime': \1", data)
    data = data.replace("True", "true")
    data = data.replace("False", "false")
    data = data.replace("u'", "'")
    data = data.replace("\n", "")
    data = data.replace("'", "\"")
    return data


def send_syslog_tls(server_url, port, data):

    unsecured_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = ssl.wrap_socket(unsecured_client_socket,
                                    ca_certs=config.get('general', 'ca_cert'),
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ssl_version=ssl.PROTOCOL_TLSv1)
    client_socket.connect((server_url, port))
    client_socket.send(data)
    client_socket.close()


def parse_cb_defense_response(response):
    version = 'CEF:0'
    vendor = 'Confer'
    product = 'Confer_Syslog_Connector'
    dev_version = '2.0'
    splitDomain = True

    log_messages = []

    if response[u'success']:

        if len(response[u'notifications']) < 1:
            logger.info('successfully connected, no alerts at this time')
            sys.exit(0)

        for note in response[u'notifications']:
            if 'type' not in note:
                note['type'] = 'THREAT'

            if note['type'] == 'THREAT':
                signature = 'Active_Threat'
                seconds = str(note['threatInfo']['time'])[:-3]
                name = str(note['threatInfo']['summary'])
                severity = str(note['threatInfo']['score'])
                device_name = str(note['deviceInfo']['deviceName'])
                user_name = str(note['deviceInfo']['email'])
                device_ip = str(note['deviceInfo']['internalIpAddress'])
                link = str(note['url'])
                tid = str(note['threatInfo']['incidentId'])
                timestamp = time.strftime("%b %d %Y %H:%M:%S", time.localtime(int(seconds)))
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
                severity = ''
                seconds = str(note['eventTime'])[:-3]
                timestamp = time.strftime("%b %d %Y %H:%M:%S", time.localtime(int(seconds)))
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
                                 'extension': extension})
    return log_messages


def verify_config_parse_servers():

    server_list = []

    #
    # Sanity check the general stanza this includes the tcp/tls host, port, template, and cert
    #
    if not config.get('general', 'tcp_tls_host'):
        logger.error('Error: A tcp_tls_host is required in the general stanza')
        sys.exit(-1)
    if not config.get('general', 'tcp_tls_port'):
        logger.error('Error: A tcp_tls_port isrequired in the general stanza')
        sys.exit(-1)
    if not config.get('general', 'template'):
        logger.error('Error: A template is required in the general stanza')
        sys.exit(-1)
    if not config.get('general', 'ca_cert'):
        logger.error('Error: A ca_cert is required in general stanza')
        sys.exit(-1)

    #
    # Sanity check the port
    #
    try:
        int(config.get('general', 'tcp_tls_port'))
    except Exception as e:
        logger.error(e.message)
        logger.error("Error: tcp_tls_port must be an integer")
        sys.exit(-1)

    #
    # Parse out multiple servers
    #
    for section in config.sections():
        server = {}
        if section == 'general':
            #
            # ignore the general section
            #
            continue
        if config.has_option(section,'server_url') and \
                config.has_option(section,'connector_id') and \
                config.has_option(section, 'api_key'):

            server['server_url'] = config.get(section, 'server_url')
            server['connector_id'] = config.get(section, 'connector_id')
            server['api_key'] = config.get(section, 'api_key')
            server_list.append(server)
        else:
            logger.error("The {} section does not contain the necessary arguments".format(section))
            sys.exit(-1)

    return server_list


def main():

    config = parse_config()
    if not config:
        logger.error("Error parsing config file")
        sys.exit(-1)

    #
    # verify the config file and get the Cb Defense Server list
    #
    server_list = verify_config_parse_servers()

    #
    # Error or not, there is nothing to do
    #
    if len(server_list) == 0:
        logger.info("Error: no configured Cb Defense Servers")
        sys.exit(-1)

    logger.info("Found {} Cb Defense Servers in config file".format(len(server_list)))

    #
    # Iterate through our Cb Defense Server list
    #
    for server in server_list:
        logger.info("Handling notifications for {}".format(server.get('server_url')))

        if args.debug:
            p = json.dumps(test_data)
            json_response = json.loads(p)
        else:
            response = cb_defense_server_request(server.get('server_url'),
                                                 server.get('defense_api_key'),
                                                 server.get('connector_id'),
                                                 False)

            #
            # perform fixups
            #
            response = fix_response(response.content)
            json_response = json.loads(response)

            if not response:
                logger.error("Error: got no response from Cb Defense Server")
                sys.exit(-1)

        #
        # parse the Cb Defense Response and get a list of log messages to send to tcp_tls_host:tcp_tls_port
        #
        log_messages = parse_cb_defense_response(json_response)
        if not log_messages:
            logger.info("There are no messages to forward to tcp+tls host")
            sys.exit(0)

        logger.info("Sending {} messages to {}:{}".format(len(log_messages),
                                                          config.get('general', 'tcp_tls_host'),
                                                          config.get('general', 'tcp_tls_port')))

        #
        # finally send the messages
        #
        for log in log_messages:
            template = Template(config.get('general', 'template'))
            send_syslog_tls(config.get('general', 'tcp_tls_host'),
                            int(config.get('general', 'tcp_tls_port')),
                            template.render(log))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config-file', help="Absolute path to configuration file")
    parser.add_argument('--debug', action="store_true")
    parser.add_argument('--log-file', help="Log file location")

    global args
    args = parser.parse_args()
    if not args.config_file:
        logger.error("Error: a config file must be supplied")
        sys.exit(-1)

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if args.debug:
        from test_data import test_data
        logger.info("Debug mode enabled")

    try:
        main()
    except Exception as e:
        logger.error(e, exc_info=True)
        sys.exit(-1)

