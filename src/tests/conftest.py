# *******************************************************
# Copyright (c) VMware, Inc. 2020-2023. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Flask mocking app"""

import threading
import socket
# import ssl
import traceback
import json
import pprint
import logging
import pytest

from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# cert_file = '../cert.pem'
# key_file = '../cert.pem'
tcp_tls_server_port = 8888
tcp_server_port = 8887
udp_server_port = 8886


def pytest_configure():
    """Pytest Global Variables"""
    pytest.alert_search_response = {
        "num_found": 0,
        "num_available": 0,
        "results": []
    }

#
# Carbon Black Cloud Mocked Endpoints
#


@app.route('/appservices/v6/orgs/ORG_KEY/alerts/_search', methods=['POST'])
def alert_search():
    """alert_search"""
    logger.info("Fetched Alerts")
    return jsonify(pytest.alert_search_response)


#
# Syslog Output Mocked Servers
#


@app.route('/http_out', methods=['POST'])
def http_out():
    """http_out"""
    try:
        content = request.json
        logger.info(content)
    except Exception:
        logger.info(traceback.format_exc())
    return jsonify({})


def udp_server_func():
    """udp_server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('0.0.0.0', udp_server_port)
    print("udp_server is listening on port {}".format(udp_server_port))
    sock.bind(server_address)

    while True:
        data, address = sock.recvfrom(4096)
        print(address)
        print(len(data))
        print(repr(data))


def tcp_server_func():
    """tcp_server"""
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', tcp_server_port))
    server_socket.listen(1)
    print("tcp_server is listening on port {}".format(tcp_server_port))

    while True:
        new_client_socket, address = server_socket.accept()

        secured_client_socket = new_client_socket

        print(new_client_socket, address)
        buffer = secured_client_socket.recv(4096)
        print(len(buffer))
        try:
            pprint.pprint(json.loads(buffer))
        except Exception:
            print(buffer)
            pass
        secured_client_socket.close()


# def tcp_tls_server_func():
#     """tcp_tls_server"""
#     # Create a TCP/IP socket
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind(('0.0.0.0', tcp_tls_server_port))
#     server_socket.listen(1)
#     print("tcp_tls_server is listening on port {}".format(tcp_tls_server_port))
#
#     while True:
#         new_client_socket, address = server_socket.accept()
#
#         secured_client_socket = ssl.wrap_socket(new_client_socket,
#                                                 server_side=True,
#                                                 certfile=cert_file,
#                                                 keyfile=key_file,
#                                                 ssl_version=ssl.PROTOCOL_TLSv1)

        print(new_client_socket, address)
        buffer = secured_client_socket.recv()
        print(len(buffer))
        print(repr(buffer))
        secured_client_socket.close()


#
# Create a listening server to test UDP, TCP and TCP/TLS
#
tcp_server = threading.Thread(target=lambda: tcp_server_func, daemon=True).start()
# tcp_tls_server = threading.Thread(target=lambda: tcp_tls_server, daemon=True).start()
udp_server = threading.Thread(target=lambda: udp_server_func, daemon=True).start()

#
# Default port is 5000
#
http_server = threading.Thread(daemon=True, target=lambda: app.run(host='0.0.0.0',
                                                                   port=5001,
                                                                   debug=True,
                                                                   use_reloader=False,
                                                                   ssl_context='adhoc')).start()
