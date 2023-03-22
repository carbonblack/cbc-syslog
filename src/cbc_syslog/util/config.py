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

"""Config class"""

import configparser
import json
import logging

log = logging.getLogger(__name__)


class Config:
    """
    Configuration Manager

    Example:
        [general]
        template =
        back_up_dir =
        output_format=
        output_type=
        tcp_out=
        udp_out=
        http_out=
        http_headers=
        https_ssl_verify=

        [tls]
        ca_cert =
        cert =
        key =
        key_password =
        tls_verify =

        [org1]
        custom_api_id =
        custom_api_key =
        org_key =
        server_url =
    """

    config = None

    OUTPUT_TYPES = ["tcp", "udp", "tcp+tls", "http"]

    DEFAULT_CEF_TEMPLATE = "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}"  # noqa 501
    DEFAULT_LEEF_TEMPLATE = ""
    OUTPUT_FORMATS = ["cef", "leef", "json"]
    TEMPLATE_SUPPORTED_FORMATS = ["cef", "leef"]

    def __init__(self, file_path):
        """
        Initialize the Config object.

        Args:
            file_path (str): File path to the config file to be parsed.
        """
        self.config = configparser.ConfigParser()

        # Read config from file
        self.config.read(file_path)
        print(f"Sections: {self.config.sections()}")

    def validate(self):
        """
        Validate configuration for required properties and supported values

        Returns:
            bool: Whether the config is validd
        """
        valid = True

        if not self.config.has_option("general", "back_up_dir"):
            log.error("Section (general): back_up_dir required to save output in case of a destination failure")
            valid = False

        # Verify output_format and their required properties
        if not self.config.has_option("general", "output_format"):
            log.error("Section (general): output_format required")
            valid = False
        elif self.config.get("general", "output_format").lower() not in self.OUTPUT_FORMATS:
            format = self.config.get("general", "output_format")
            log.error(f"Section (general): output_format {format} is not a supported format")
            valid = False
        elif self.config.get("general", "output_format").lower() in self.TEMPLATE_SUPPORTED_FORMATS:
            if not self.config.has_option("general", "template"):
                format = self.config.get("general", "output_format").lower()
                if format == "cef":
                    log.warning(f"Section (general): template missing using default {self.DEFAULT_CEF_TEMPLATE}")
                elif format == "leef":
                    log.warning(f"Section (general): template missing using default {self.DEFAULT_LEEF_TEMPLATE}")

        # Verify output_type and their required properties
        if not self.config.has_option("general", "output_type"):
            log.error("Section (general): output_type required")
            valid = False
        elif "tcp" in self.config.get("general", "output_type").lower():
            if not self.config.has_option("general", "tcp_out"):
                log.error("Section (general): tcp_out required when output_type is tcp or tcp+tls")
                valid = False
            elif ":" not in self.config.get("general", "tcp_out"):
                log.error("Section (general): tcp_out must be of format <ip>:<port>")
                valid = False

            # Verify TLS required properties
            if "+tls" in self.config.get("general", "output_type").lower():
                if not self.config.has_option("tls", "tls_verify"):
                    log.warning("Section (tls): tls_verify not specified defaulting to TRUE")

                if not self.config.has_option("tls", "ca_cert"):
                    log.error("Section (tls): ca_cert required when output_type is tcp+tls")
                    valid = False

                if self.config.has_option("tls", "cert") and not self.config.has_option("tls", "key"):
                    log.error("Section (tls): key must be specified when a cert is provided")
                    valid = False

        elif "udp" == self.config.get("general", "output_type").lower():
            if not self.config.has_option("general", "udp_out"):
                log.error("Section (general): udp_out required when output_type is udp")
                valid = False
            elif ":" not in self.config.get("general", "udp_out"):
                log.error("Section (general): udp_out must be of format <ip>:<port>")
                valid = False

        elif "http" == self.config.get("general", "output_type").lower():
            if not self.config.has_option("general", "http_out"):
                log.error("Section (general): http_out required when output_type is http")
                valid = False
            if self.config.has_option("general", "http_headers"):
                try:
                    json.loads(self.config.get("general", "http_headers"))
                except ValueError:
                    log.error("Section (general): http_headers is not valid json must follow format {'content-type': 'application/json'}")  # noqa 501
                    valid = False
            if not self.config.has_option("general", "https_ssl_verify"):
                log.warning("Section (general): https_ssl_verify not specified defaulting to TRUE")

        # Check for Carbon Black Cloud instances
        has_server = False
        for section in self.config.sections():
            if self.config.has_option(section, "server_url"):
                # Verify the instance has the required credentials
                if not self.config.has_option(section, "custom_api_id"):
                    log.error(f"Carbon Black Cloud instance ({section}): Missing custom_api_id")
                    valid = False

                elif not self.config.has_option(section, "custom_api_key"):
                    log.error(f"Carbon Black Cloud instance ({section}): Missing custom_api_key")
                    valid = False

                elif not self.config.has_option(section, "org_key"):
                    log.error(f"Carbon Black Cloud instance ({section}): Missing org_key")
                    valid = False

                else:
                    has_server = True

        if not has_server:
            log.error("No valid Carbon Black Cloud instances provided")
            return False

        return valid

    def output(self):
        """Output properties"""
        pass

    def sources(self):
        """Carbon Black Cloud instances"""
        pass
