import hashlib
import json
import os
import requests
import socket
import ssl

from jinja2 import Template

import logging
import logging.handlers
import traceback

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def delete_stored_data(back_up_dir, hash):
    try:
        os.remove("{}{}".format(back_up_dir, hash))
    except Exception:
        logger.error(traceback.format_exc())


def store_data(back_up_dir, data):
    byte_data = data.encode("utf-8")
    hash = hashlib.sha256(byte_data).hexdigest()
    try:
        with open("{}{}".format(back_up_dir, hash), 'wb') as f:
            f.write(byte_data)
        return hash
    except Exception:
        logger.error(traceback.format_exc())
        logger.error('Unable to store data to {}'.format(back_up_dir))
        return None


def send_syslog(output_params, data):
    retval = True
    client_socket = None

    output_type = output_params['output_type']
    server_url = output_params['output_host']
    port = output_params['output_port']

    if output_type == 'tcp+tls':
        unsecured_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=output_params['ca_cert'])
            if 'tls_cert' in output_params:
                context.load_cert_chain(output_params['tls_cert'],
                                        keyfile=output_params['tls_key'],
                                        password=output_params['tls_key_password'])

            if not output_params['tls_verify']:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            client_socket = context.wrap_socket(unsecured_client_socket, server_hostname=server_url)

            client_socket.connect((server_url, port))
            client_socket.send(data.encode("utf-8"))
        except Exception:
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
        except Exception:
            logger.error(traceback.format_exc())
            retval = False
        finally:
            if client_socket:
                client_socket.close()

    elif output_type == 'udp':
        unsecured_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            unsecured_client_socket.sendto(data.encode("utf-8"), (server_url, port))
        except Exception:
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
                                 verify=output_params['https_ssl_verify'])
            logger.info(resp)
        except Exception:
            logger.error(traceback.format_exc())
            retval = False

    return retval


def send_stored_data(output_params):
    back_up_dir = output_params['back_up_dir']
    logger.info("Number of files in store forward: {0}".format(len(os.listdir(back_up_dir))))
    for file_name in os.listdir(back_up_dir):
        file_data = open("{}{}".format(back_up_dir, file_name), 'rb').read()
        file_data = file_data.decode("utf-8")
        if send_syslog(output_params, file_data):
            # If the sending was successful, delete the stored data
            delete_stored_data(back_up_dir, file_name)


def send_new_data(output_params, log_messages):

    if log_messages is None:
        logger.info("There are no messages to forward to host")
        return
    elif output_params['output_port']:
        logger.info("Sending {0} messages to {1}:{2}".format(len(log_messages),
                                                             output_params['output_host'],
                                                             output_params['output_port']))
    else:
        logger.info("Sending {0} messages to {1}".format(len(log_messages),
                                                         output_params['output_host']))

    output_format = output_params['output_format']
    for log in log_messages:

        if output_format == 'json':
            final_data = json.dumps(log) + '\n'
        elif output_format == 'cef':
            template = Template(output_params['template'])
            final_data = template.render(log) + '\n'
        elif output_format == 'leef':
            final_data = log

        # Store notifications just in case sending fails
        hash = store_data(output_params['back_up_dir'], final_data)

        if send_syslog(output_params, final_data):
            # If successful send, then we just delete the stored version
            if hash:
                delete_stored_data(output_params['back_up_dir'], hash)
