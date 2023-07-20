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

import logging
import pathlib
import pytest
import socket
import ssl
import time
import threading
import traceback

from flask import Flask, request, jsonify, abort

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

CERTS_PATH = pathlib.Path(__file__).joinpath("../fixtures/certs").resolve()
TMP_PATH = pathlib.Path(__file__).joinpath("../fixtures/tmp").resolve()

app = Flask(__name__)

tcp_tls_server_port = 8888
tcp_server_port = 8887
udp_server_port = 8886


@pytest.fixture(scope="function", autouse=True)
def test_globals():
    """Pytest Global Variables"""
    pytest.alert_search_request = None
    pytest.alert_search_response = None
    pytest.audit_log_response = None
    pytest.tcp_recv_data = None
    pytest.tcp_tls_recv_data = None
    pytest.udp_recv_data = None
    pytest.http_recv_data = None
    pytest.recv_history = []


@pytest.fixture(scope="function")
def wipe_tmp():
    """Wipe tmp fixtures before each test"""
    for file_path in TMP_PATH.iterdir():
        if file_path.name != "KEEP_EMPTY.md":
            file_path.unlink(missing_ok=True)

    # Add small delay to prevent race condition
    time.sleep(0.1)


#
# Carbon Black Cloud Mocked Endpoints
#
@app.route('/appservices/v6/orgs/<org_key>/alerts/_search', methods=['POST'])
def alert_search(org_key):
    """alert_search"""
    log.info("Fetched Alerts")

    # Save the request for verification
    pytest.alert_search_request = request.get_json()

    output = {
        "num_found": 0,
        "num_available": 0,
        "results": []
    }
    if callable(pytest.alert_search_response):
        output = pytest.alert_search_response(pytest.alert_search_request)
    elif isinstance(pytest.alert_search_response, int):
        abort(pytest.alert_search_response)
    else:
        output = pytest.alert_search_response

    return jsonify(output)


@app.route('/integrationServices/v3/auditlogs', methods=['GET'])
def audit_log():
    """alert_search"""
    log.info("Fetched Audit Logs")
    if callable(pytest.audit_log_response):
        output = pytest.audit_log_response()
    elif isinstance(pytest.audit_log_response, int):
        abort(pytest.audit_log_response)
    else:
        output = pytest.audit_log_response
    return jsonify(output)


#
# Syslog Output Mocked Servers
#
@app.route('/http_out', methods=['POST'])
def http_out():
    """http_out"""
    try:
        log.debug(f"New data length: {len(request.data)}")
        pytest.http_recv_data = request.data
        pytest.recv_history.append(request.data)
    except Exception:
        log.info(traceback.format_exc())
    return jsonify({})


def udp_server_func():
    """udp_server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ('0.0.0.0', udp_server_port)
    log.info(f"udp_server is listening on port {udp_server_port}")
    sock.bind(server_address)

    while True:
        buffer, address = sock.recvfrom(4096)
        log.debug(f"New client from {address}")
        log.debug(f"Buffer length: {len(buffer)}")
        pytest.udp_recv_data = buffer
        pytest.recv_history.append(buffer)


def tcp_server_func():
    """tcp_server"""
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', tcp_server_port))
    server_socket.listen(1)
    log.info(f"tcp_server is listening on port {tcp_server_port}")

    while True:
        unsecured_client_socket, address = server_socket.accept()

        log.debug(f"New client: {unsecured_client_socket} from {address}")
        buffer = unsecured_client_socket.recv(4096)
        log.debug(f"Buffer length: {len(buffer)}")

        # Save contents for testing
        pytest.tcp_recv_data = buffer
        pytest.recv_history.append(buffer)


def tcp_tls_server_func():
    """tcp_tls_server"""
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', tcp_tls_server_port))
    server_socket.listen(1)
    log.info(f"tcp_tls_server is listening on port {tcp_tls_server_port}")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTS_PATH.joinpath("rootCACert.pem"),
                            keyfile=CERTS_PATH.joinpath("rootCAKey.pem"))

    while True:
        new_client_socket, address = server_socket.accept()
        try:
            with context.wrap_socket(new_client_socket, server_side=True) as secured_client_socket:
                log.debug(f"New client: {new_client_socket} from {address}")
                buffer = secured_client_socket.recv(4096)
                log.debug(f"Buffer length: {len(buffer)}")

                # Save contents for testing
                pytest.tcp_tls_recv_data = buffer
                pytest.recv_history.append(buffer)

        except Exception as e:
            pytest.exception = e


#
# Create a listening server to test UDP, TCP and TCP/TLS
#
tcp_server = threading.Thread(daemon=True, target=tcp_server_func).start()
tcp_tls_server = threading.Thread(daemon=True, target=tcp_tls_server_func).start()
udp_server = threading.Thread(daemon=True, target=udp_server_func).start()

#
# Default port is 5000
#
http_server = threading.Thread(daemon=True, target=lambda: app.run(host='0.0.0.0',
                                                                   port=5001,
                                                                   debug=True,
                                                                   use_reloader=False,
                                                                   ssl_context='adhoc')).start()
