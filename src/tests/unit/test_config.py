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

"""Tests for the Config object."""

import pytest
import pathlib
from cbc_syslog.util import Config

FIXTURES_PATH = pathlib.Path(__file__).joinpath("../../fixtures").resolve()


@pytest.mark.parametrize("file_path, valid", [
    ("confs/cef.conf", True),
    ("confs/json.conf", True),
    ("confs/leef.conf", True)
])
def test_validate(file_path, valid):
    """Test Validate"""
    resolved_path = str(FIXTURES_PATH.joinpath(file_path))
    config = Config(resolved_path)
    assert config.validate()


@pytest.mark.parametrize("file_path, valid, logs", [
    ("confs/invalid.conf", True, [
        "Section (general): back_up_dir required to save output in case of a destination failure",
        "Section (general): output_format required",
        "Section (general): output_type required",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("confs/invalid-http.conf", True, [
        "Section (general): output_format required",
        "Section (general): http_out required when output_type is http",
        "Section (general): https_ssl_verify not specified defaulting to TRUE",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing custom_api_id",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("confs/invalid-tcp.conf", True, [
        "Section (general): output_format required",
        "Section (general): tcp_out required when output_type is tcp or tcp+tls",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing org_key",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("confs/invalid-udp.conf", True, [
        "Section (general): output_format required",
        "Section (general): udp_out required when output_type is udp",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing custom_api_id",
        "No valid Carbon Black Cloud instances provided"
    ])
])
def test_validate_invalid(file_path, valid, caplog, logs):
    """Test Validate"""
    resolved_path = str(FIXTURES_PATH.joinpath(file_path))
    config = Config(resolved_path)
    assert not config.validate()

    for index, record in enumerate(caplog.records):
        assert record.msg == logs[index]
