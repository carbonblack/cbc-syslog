import ast
import os
import sys

from .six import PY2
from .six.moves.configparser import ConfigParser

import logging
import logging.handlers
import traceback

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def parse_config(config_file):
    """
    parse the config file into globals
    :return:
    """
    try:
        config = ConfigParser()
        if PY2:
            config.readfp(open(config_file))
        else:
            config.read_file(open(config_file))

    except Exception as e:
        logging.error(e, exc_info=True)
        logger.error("Error parsing config file")
        sys.exit(-1)
    else:
        return config


def verify_config(config):
    """
    Validate configuration parameters
    """
    output_params = {}
    server_list = []

    #
    # Verify output_format
    #

    if not config.has_option('general', 'output_format'):
        logger.error('No output_format specified')
        logger.warn('Defaulting output format to CEF')
        config.set('general', 'output_format', 'cef')

    output_format = config.get('general', 'output_format').lower()

    if not output_format == 'cef' and not output_format == 'json' and not output_format == 'leef':
        logger.error('Invalid output_format type was specified. Supported values: JSON, CEF, or LEEF')
        logger.warn('Defaulting output format to CEF')
        output_format = 'cef'

    if output_format == 'cef' and not config.has_option('general', 'template'):
        logger.error('A template is required in the general stanza when output format is CEF')
        sys.exit(-1)
    elif output_format == 'cef':
        output_params['template'] = config.get('general', 'template')

    if not config.has_option('general', 'output_type'):
        logger.error('An output_type is required in the general stanza')
        sys.exit(-1)

    output_type = config.get('general', 'output_type')
    if output_type not in ['tcp', 'udp', 'tcp+tls', 'http']:
        logger.error('output_type is invalid.  Must be tcp, udp, http or tcp+tls')
        sys.exit(-1)

    back_up_dir = config.get('general', 'back_up_dir')
    # Add trailing slash
    if back_up_dir[-1] != '/' and back_up_dir[-1] != '\\':
        if back_up_dir.find('/') == -1:
            output_params['back_up_dir'] = back_up_dir + '\\'
        else:
            output_params['back_up_dir'] = back_up_dir + '/'
    else:
        output_params['back_up_dir'] = back_up_dir

    output_params['output_type'] = output_type
    output_params['output_format'] = output_format

    try:
        output_params['policy_action_severity'] = config.get('general', 'policy_action_severity')
    except Exception:
        output_params['policy_action_severity'] = 1

    if output_type == 'tcp':
        if not config.has_option('general', 'tcp_out'):
            logger.error('tcp_out parameter is required for tcp output_type')
            sys.exit(-1)

        try:
            output_params['output_host'] = config.get('general', 'tcp_out').strip().split(":")[0]
            output_params['output_port'] = int(config.get('general', 'tcp_out').strip().split(':')[1])
        except Exception:
            logger.error(traceback.format_exc())
            logger.error("tcp_out must be of format <ip>:<port>")
            sys.exit(-1)

    elif output_type == 'udp':
        if not config.has_option('general', 'udp_out'):
            logger.error('udpout parameter is required for udp output_type')
            sys.exit(-1)
        try:
            output_params['output_host'] = config.get('general', 'udp_out').strip().split(":")[0]
            output_params['output_port'] = int(config.get('general', 'udp_out').strip().split(':')[1])
        except Exception:
            logger.error(traceback.format_exc())
            logger.error("udp_out must be of format <ip>:<port>")
            sys.exit(-1)

    elif output_type == 'tcp+tls':
        if not config.has_option('tls', 'tls_verify'):
            logger.error("Must specify tls_verify in config file")
            sys.exit(-1)
        else:
            output_params['tls_verify'] = config.get('tls', 'tls_verify')

        if not config.has_option('tls', 'ca_cert'):
            logger.error("Must specify ca_cert file path in the general stanza")
            sys.exit(-1)
        else:
            output_params['ca_cert'] = config.get('tls', 'ca_cert')

        if config.has_option('tls', 'cert') != config.has_option('tls', 'key'):
            logger.error("You cannot specify a TLS cert without specifying a TLS key")
            sys.exit(-1)
        else:
            output_params['tls_cert'] = config.get('tls', 'cert')
            output_params['tls_key'] = config.get('tls', 'key')

            try:
                output_params['tls_key_password'] = config.get('tls', 'key_password')
            except Exception:
                output_params['tls_key_password'] = None

        try:
            output_params['tls_verify'] = config.getboolean('tls', 'tls_verify')
        except ValueError:
            logger.error(traceback.format_exc())
            logger.error("tls_verify must be either true or false")
            sys.exit(-1)

        try:
            output_params['output_host'] = config.get('general', 'tcp_out').strip().split(":")[0]
            output_params['output_port'] = int(config.get('general', 'tcp_out').strip().split(':')[1])
        except Exception:
            logger.error(traceback.format_exc())
            logger.error("tcp_out must be of format <ip>:<port>")
            sys.exit(-1)

    elif output_type == 'http':
        try:
            output_params['output_host'] = config.get('general', 'http_out')
            output_params['output_port'] = None
        except Exception:
            logger.error(traceback.format_exc())
            logger.error("http_out must be of format http(s)://<ip>:<port>")
            sys.exit(-1)

        output_params['http_headers'] = {'content-type': 'application/json'}
        if config.has_option('general', 'http_headers'):
            try:
                headers = config.get('general', 'http_headers').strip()    # Get the headers from config file
                output_params['http_headers'] = ast.literal_eval(headers)  # Convert the str to a dict
            except Exception as e:
                logger.error(str(e))
                logger.error("Invalid http_headers: unable to parse JSON")
                sys.exit(-1)

        if config.has_option('general', 'https_ssl_verify'):
            output_params['https_ssl_verify'] = False if \
                config.get('general', 'https_ssl_verify') in ['False', 'false', '0'] else True
        else:
            output_params['https_ssl_verify'] = True

        output_params['requests_ca_cert'] = "/usr/share/cb/integrations/cbc-syslog/cacert.pem"
        if config.has_option('general', 'requests_ca_cert'):
            output_params['requests_ca_cert'] = config.get('general', 'requests_ca_cert')

        if os.path.isfile(output_params['requests_ca_cert']):
            os.environ["REQUESTS_CA_BUNDLE"] = output_params['requests_ca_cert']

    #
    # Parse out servers
    #
    for section in config.sections():
        server = {}
        if section == 'general' or section == 'tls':
            continue  # ignore the non server sections section
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

        if 'server_url' not in server or 'api_connector_id' not in server or 'api_key' not in server:
            logger.error("The {0} section does not contain the necessary Carbon Black Cloud parameters".format(section))
            sys.exit(-1)

        server['source'] = section
        server_list.append(server)

    # Unable to fetch data without any servers
    if server_list == []:
        logger.info("No configured Carbon Black Cloud Servers")
        sys.exit(-1)

    return output_params, server_list
