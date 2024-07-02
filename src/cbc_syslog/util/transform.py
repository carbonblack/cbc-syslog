
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

"""Transform class"""

import logging

from datetime import datetime
from jinja2 import Template


log = logging.getLogger(__name__)


class Transform:
    """
    Transform data (dict) into templated syslog message (str)

    Syslog Message (RFC 5424)

        The following header components need to be provided in the template string to be compliant with RFC 5424
        {{ datetime_utc or datetime_legacy }} <host> <format>

        datetime_utc = 2023-01-18T11:07:53.000052Z
        datetime_legacy = Jan 18 11:07:53

        datetime needs to be a dynamic parameter where as host and format need hardcoded in the template

    """

    utc_time_format = "%Y-%m-%dT%H:%M:%S.%fZ"  # e.g. 1985-04-12T23:20:50.52Z
    legacy_time_format = "%b %d %H:%M:%S"  # e.g. Jan 18 11:07:53

    vendor = "CarbonBlack"
    product = "CBCSyslog"

    from .. import __version__
    product_version = __version__

    def __init__(self, **kwargs):
        """
        Initialize the Transform object.

        Args:
            **template (str): Template for data to be transformed
            **extension (dict): Lookup table for custom extension by type
            **type_field (str): Field name in the data to be render which indicates the type for customizing the extension
            **time_format (str): Custom timestamp format for timestamp fields
            **time_fields (list): List of strings representing the timestamp fields to be converted
        """
        self.template = Template(kwargs.get("template", ""))
        self.type_field = kwargs.get("type_field", None)
        self.time_format = kwargs.get("time_format", None)
        self.time_fields = kwargs.get("time_fields", [])

        self.extension_templates = {}
        extension = kwargs.get("extension", {})
        for key in extension:
            self.extension_templates[key] = Template(extension[key])

    def render(self, data):
        """
        Render the data as the transformed str

        Args:
            data (dict): JSON formatted data to be transformed

        Returns:
            (str): Rendered syslog message based on the template and extension configured
        """
        now = datetime.utcnow()

        defaulted_data = {
            "datetime_utc": now.strftime(self.utc_time_format),
            "datetime_legacy": now.strftime(self.legacy_time_format),
            "vendor": self.vendor,
            "product": self.product,
            "product_version": self.product_version,
            **data
        }

        # Reformat timestamps based on configuration
        for field in self.time_fields:
            if field not in data:
                continue
            try:
                if isinstance(data[field], str):
                    timestamp = datetime.strptime(data[field], "%Y-%m-%dT%H:%M:%S.%fZ")
                elif isinstance(data[field], int):
                    timestamp = datetime.fromtimestamp(data[field])
                else:
                    continue
                defaulted_data[field] = timestamp.strftime(self.time_format)
            except:
                continue

        # Attempt to build extension based on type supported extension templates
        type = data.get(self.type_field, "default")
        if type in self.extension_templates:
            extension = self.extension_templates[type].render(defaulted_data)
        else:
            extension = ""
        defaulted_data["extension"] = extension

        return self.template.render(defaulted_data)
