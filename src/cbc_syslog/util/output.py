
# *******************************************************
# Copyright (c) Broadcom, Inc. 2020-2024. All Rights Reserved. Carbon Black.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Output class"""

import base64
import logging
import pathlib
import requests
import socket
import ssl
import traceback

from datetime import datetime, timezone

log = logging.getLogger(__name__)


class Output:
    """Output mechanisms to send data to local or external destination"""

    def __init__(self, **kwargs):
        """
        Initialize the Output object.

        Args:
            **type (str): The mechanism to send the output. Supports: tcp, tcp+tls, udp, http and file
            **host (str): The host of the destination.
            **port (str): The port of the destination.
            **tls_verify (bool): Whether to verify TLS.
            **http_headers (dict): Dictionary of header names and values to append to http request.
            **ca_cert (str): The CA_CERT to verify location
            **cert (str): The CERT to add the cert chain
            **key (str): The key use to protect the cert
            **key_password (str): The password for the key
        """
        self.output_params = kwargs

    def send(self, data):
        """
        Send data to configured destination.

        Args:
            data (str): The content to be sent
        """
        success = True
        client_socket = None

        encoded_data = data.encode("utf-8")

        type = self.output_params.get("type").lower()
        server_url = self.output_params.get("host")
        port = self.output_params.get("port")

        if "tcp" in type:
            unsecured_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if "tls" in type:
                    context = ssl.create_default_context()
                    context.load_verify_locations(self.output_params["ca_cert"])

                    if "cert" in self.output_params:
                        context.load_cert_chain(self.output_params["cert"],
                                                keyfile=self.output_params["key"],
                                                password=self.output_params["key_password"])

                    if not self.output_params.get("tls_verify", True):
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    client_socket = context.wrap_socket(unsecured_client_socket, server_hostname=server_url)
                else:
                    client_socket = unsecured_client_socket

                client_socket.connect((server_url, int(port)))
                client_socket.sendall(encoded_data)
            except Exception:
                log.error(traceback.format_exc())
                success = False
            finally:
                if client_socket:
                    client_socket.close()

        elif type == "udp":
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                client_socket.sendto(encoded_data, (server_url, int(port)))
            except Exception:
                log.error(traceback.format_exc())
                success = False
            finally:
                if client_socket:
                    client_socket.close()

        elif type == "http":
            try:
                resp = requests.post(headers=self.output_params.get("http_headers", {}),
                                     url=server_url,
                                     data=encoded_data,
                                     verify=self.output_params.get("tls_verify", True))
                log.info(resp)
            except Exception:
                log.error(traceback.format_exc())
                success = False

        elif type == "file":
            try:
                encoded = base64.b64encode(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:00.000Z').encode("ascii"))
                file_name = f"{encoded.decode('ascii')}.txt"
                new_file_path = pathlib.Path(self.output_params.get("file_path")).joinpath(file_name)
                with open(new_file_path, "a") as new_file:
                    new_file.write(data + "\n")
            except Exception:
                log.error(traceback.format_exc())
                success = False

        else:
            log.error(f"type {type} not supported")
            success = False

        return success
