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
        backup_dir = str
        output_format = str
        output_type = str
        tcp_out = str
        udp_out = str
        http_out = str
        http_headers = dict
        https_ssl_verify = bool
        file_path = str

        [tls]
        ca_cert = str
        cert = str
        key = str
        key_password = str
        tls_verify = bool

        [alerts_template]
        template = str
        type_field = str
        time_format = str
        time_fields = list

        [alerts_template.extension]
        default = str

        [audit_logs_template]
        template = str
        type_field = str
        time_format = str
        time_fields = list

        [audit_logs_template.extension]
        default = str

        [org1]
        custom_api_id = str
        custom_api_key = str
        org_key = str
        server_url = str
        alerts_enabled = bool
        audit_logs_enabled = bool

        [[or1.alert_rules]]
        str = str
    """
    OUTPUT_TYPES = ["tcp", "udp", "tcp+tls", "http", "file"]
    OUTPUT_FORMATS = ["json", "template"]
    SUPPORTED_TEMPLATES = ["alerts_template", "audit_logs_template"]

    def __init__(self, file_path):
        """
        Initialize the Config object.

        Args:
            file_path (str): File path to the config file to be parsed.
        """
        # Read config from file
        with open(file_path, "rb") as f:
            self.config = tomllib.load(f)

    def get(self, key, default=None):
        """
        Get single parameter with support for dot notation nested navigation

        Args:
            key (str): The config key to fetch
            default (*): The value to return in case key is not found
        """
        if "." in key:
            keys = key.split(".")
        else:
            keys = list(key)

        try:
            new_dict = self.config
            for step in keys:
                new_dict = new_dict.get(step, None)
                if new_dict is None:
                    return default
                elif not isinstance(new_dict, dict):
                    return new_dict
        except:
            return default

        return new_dict

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

        if "backup_dir" not in general_section:
            log.error("Section (general): backup_dir required to save output in case of a destination failure")
            valid = False

        # Verify output_format and their required properties
        if "output_format" not in general_section:
            log.error("Section (general): output_format required")
            valid = False
        elif general_section.get("output_format").lower() not in self.OUTPUT_FORMATS:
            format = general_section.get("output_format")
            log.error(f"Section (general): output_format {format} is not a supported format")
            valid = False
        elif general_section.get("output_format").lower() == "template":
            at_least_one = False
            for template in self.SUPPORTED_TEMPLATES:
                if template in self.config:
                    at_least_one = True
                    template_section = self.config.get(template)
                    if "template" not in template_section:
                        log.error(f"Section ({template}): missing template")
                        valid = False
                    elif "extension" in template_section.get("template"):
                        if "extension" not in template_section:
                            log.warning(f"Section ({template}): extension missing and referenced in template defaulting to empty string")
                        else:
                            if "default" not in template_section.get("extension", {}):
                                log.warning(f"Section ({template}): default extension missing if type not found defaulting to empty string")
                            elif "type_field" not in template_section:
                                log.warning(f"Section ({template}): type_field missing extension will only use default")
                    if "time_format" in template_section and len(template_section.get("time_fields", [])) < 1:
                        log.warning(f"Section ({template}): time_format specified but no time_fields listed")

            if not at_least_one:
                log.error("Section (general): output_format is template but no templates provided")
                valid = False

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

        elif "file" == general_section.get("output_type").lower():
            if "file_path" not in general_section:
                if "backup_dir" in general_section:
                    log.warning("Section (general): file_path not specified defaulting to backup_dir")
                else:
                    log.error("Section (general): file_path not specified and backup_dir missing no file destination specified")
                    valid = False

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

                if section.get("alerts_enabled", False) and "alert_rules" not in section:
                    log.warning(f"Carbon Black Cloud instance ({section_name}): Alerts enabled without"
                                f" alert_rules will result in no alerts")

                if not section.get("alerts_enabled", False) and not section.get("audit_logs_enabled", False):
                    log.error(f"Carbon Black Cloud instance ({section_name}): Has neither Alerts nor Audit logs enabled")
                    has_server = False

        if not has_server:
            log.error("No valid Carbon Black Cloud instances provided")
            return False

        return valid

    def output(self):
        """
        Output properties

        Returns:
            (dict):  output configuration

            {
                "backup_dir": "",
                "type": "",
                "host": "",
                "port": "",
                "tls_verify": "",
                "http_headers": "",
                "ca_cert": "",
                "cert": "",
                "key": "",
                "key_password": "",
                "file_path": ""
            }
        """
        general_section = self.config.get("general", {})
        tls_section = self.config.get("tls", {})

        params = {
            "backup_dir": general_section.get("backup_dir"),
            "type": general_section.get("output_type").lower(),
            "host": None,
            "port": None
        }

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

        elif "file" in params["type"]:
            del params["host"]
            del params["port"]

            # Default backup_dir if file_path missing
            params["file_path"] = general_section.get("file_path", general_section.get("backup_dir"))

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
                # Check for missing https and extra backslash
                url = section.get("server_url")
                if "://" not in url:
                    url = "https://" + url
                if url[-1] == "/":
                    url = url[:-1]

                sources.append({
                    "custom_api_id": section.get("custom_api_id"),
                    "custom_api_key": section.get("custom_api_key"),
                    "org_key": section.get("org_key"),
                    "server_url": url,
                    "alerts_enabled": section.get("alerts_enabled", False),
                    "alert_rules": section.get("alert_rules", [{}]),
                    "audit_logs_enabled": section.get("audit_logs_enabled", False),
                    "proxy": section.get("proxy", None)
                })

        return sources

    def transform(self, type):
        """
        Transform properties

        Args:
            type (str): The type of data to be transformed to correspond to the configuration

        Returns:
            (dict): transform configuration
        """
        general_section = self.config.get("general", {})
        format = general_section.get("output_format").lower()
        if format != "template":
            return {
                "format": format
            }
        template_section = self.config.get(type + "_template", {})
        template_section["format"] = format
        return template_section
