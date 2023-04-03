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

import json
import logging

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

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
        # Read config from file
        with open(file_path, "rb") as f:
            self.config = tomllib.load(f)

    def validate(self):
        """
        Validate configuration for required properties and supported values

        Returns:
            bool: Whether the config is validd
        """
        valid = True

        general_section = self.config.get("general", {})
        if "general" not in self.config:
            log.error("Section (general): section missing")
            valid = False

        if "back_up_dir" not in general_section:
            log.error("Section (general): back_up_dir required to save output in case of a destination failure")
            valid = False

        # Verify output_format and their required properties
        if "output_format" not in general_section:
            log.error("Section (general): output_format required")
            valid = False
        elif general_section.get("output_format").lower() not in self.OUTPUT_FORMATS:
            format = general_section.get("output_format")
            log.error(f"Section (general): output_format {format} is not a supported format")
            valid = False
        elif general_section.get("output_format").lower() in self.TEMPLATE_SUPPORTED_FORMATS:
            if "template" not in general_section:
                format = general_section.get("output_format").lower()
                if format == "cef":
                    log.warning(f"Section (general): template missing using default {self.DEFAULT_CEF_TEMPLATE}")
                elif format == "leef":
                    log.warning(f"Section (general): template missing using default {self.DEFAULT_LEEF_TEMPLATE}")

        # Verify output_type and their required properties
        if "output_type" not in general_section:
            log.error("Section (general): output_type required")
            valid = False
        elif "tcp" in general_section.get("output_type").lower():
            if "tcp_out" not in general_section:
                log.error("Section (general): tcp_out required when output_type is tcp or tcp+tls")
                valid = False
            elif ":" not in general_section.get("tcp_out"):
                log.error("Section (general): tcp_out must be of format <ip>:<port>")
                valid = False

            # Verify TLS required properties
            if "+tls" in general_section.get("output_type").lower():
                # Get TLS section
                tls_section = self.config.get("tls", {})
                if "tls" not in self.config:
                    log.error("Section (tls): section missing")
                    valid = False

                if "tls_verify" not in tls_section:
                    log.warning("Section (tls): tls_verify not specified defaulting to TRUE")

                if "ca_cert" not in tls_section:
                    log.error("Section (tls): ca_cert required when output_type is tcp+tls")
                    valid = False

                if "cert" in tls_section and "key" not in tls_section:
                    log.error("Section (tls): key must be specified when a cert is provided")
                    valid = False

        elif "udp" == general_section.get("output_type").lower():
            if "udp_out" not in general_section:
                log.error("Section (general): udp_out required when output_type is udp")
                valid = False
            elif ":" not in general_section.get("udp_out"):
                log.error("Section (general): udp_out must be of format <ip>:<port>")
                valid = False

        elif "http" == general_section.get("output_type").lower():
            if "http_out" not in general_section:
                log.error("Section (general): http_out required when output_type is http")
                valid = False
            elif "://" not in general_section.get("http_out"):
                log.warning("Section (general): http_out missing protocol default to https://")

            if "http_headers" in general_section:
                try:
                    json.loads(general_section.get("http_headers"))
                except ValueError:
                    log.error("Section (general): http_headers is not valid json must follow format {'content-type': 'application/json'}")  # noqa 501
                    valid = False
            if "https_ssl_verify" not in general_section:
                log.warning("Section (general): https_ssl_verify not specified defaulting to TRUE")

        # Check for Carbon Black Cloud instances
        has_server = False
        for section_name in self.config.keys():
            section = self.config.get(section_name, {})
            # Skip properties at root level
            if type(section) is not dict:
                continue

            if "server_url" in section:
                # Verify the instance has the required credentials
                if "custom_api_id" not in section:
                    log.error(f"Carbon Black Cloud instance ({section_name}): Missing custom_api_id")
                    valid = False

                elif "custom_api_key" not in section:
                    log.error(f"Carbon Black Cloud instance ({section_name}): Missing custom_api_key")
                    valid = False

                elif "org_key" not in section:
                    log.error(f"Carbon Black Cloud instance ({section_name}): Missing org_key")
                    valid = False

                else:
                    has_server = True

        if not has_server:
            log.error("No valid Carbon Black Cloud instances provided")
            return False

        return valid

    def output(self):
        """
        Output properties

        Returns:
            (dict):  output configuration
        """
        general_section = self.config.get("general", {})
        tls_section = self.config.get("tls", {})

        params = {
            "back_up_dir": general_section.get("back_up_dir"),
            "format": general_section.get("output_format").lower(),
            "template": general_section.get("template", None),
            "type": general_section.get("output_type").lower(),
            "host": None,
            "port": None
        }

        if params["template"] is None:
            if params["format"] == "cef":
                params["template"] = self.DEFAULT_CEF_TEMPLATE
            elif params["format"] == "leef":
                params["template"] = self.DEFAULT_LEEF_TEMPLATE

        if "tcp" in params["type"]:
            params["host"], params["port"] = general_section.get("tcp_out").split(":")

            if "+tls" in params["type"]:
                params["ca_cert"] = tls_section.get("ca_cert")
                params["tls_verify"] = bool(tls_section.get("tls_verify", True))

                params["cert"] = tls_section.get("cert", None)
                params["key"] = tls_section.get("key", None)
                params["key_password"] = tls_section.get("key_password", None)

        elif "udp" in params["type"]:
            params["host"], params["port"] = general_section.get("udp_out").split(":")
        elif "http" in params["type"]:
            params["host"] = general_section.get("http_out")
            if "://" not in params["host"]:
                params["host"] = "https://" + params["host"]

            params["http_headers"] = json.loads(general_section.get("http_headers"))
            params["tls_verify"] = bool(general_section.get("https_ssl_verify", True))

        return params

    def sources(self):
        """
        Carbon Black Cloud instances

        Returns:
            (dict): sources configuration
        """
        sources = []

        for section_name in self.config.keys():
            section = self.config.get(section_name, {})
            # Skip properties at root level
            if type(section) is not dict:
                continue

            if "server_url" in section:
                sources.append({
                    "custom_api_id": section.get("custom_api_id"),
                    "custom_api_key": section.get("custom_api_key"),
                    "org_key": section.get("org_key"),
                    "server_url": section.get("server_url"),
                })

        return sources
