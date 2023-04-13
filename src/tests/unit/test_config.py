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
    ("confs/cef.toml", True),
    ("confs/json.toml", True),
    ("confs/leef.toml", True)
])
def test_validate(file_path, valid):
    """Validate supported configuration files"""
    resolved_path = str(FIXTURES_PATH.joinpath(file_path))
    config = Config(resolved_path)
    assert config.validate()


@pytest.mark.parametrize("file_path, valid, logs", [
    ("confs/invalid.toml", True, [
        "Section (general): back_up_dir required to save output in case of a destination failure",
        "Section (general): output_format required",
        "Section (general): output_type required",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("confs/invalid-http.toml", True, [
        "Section (general): output_format required",
        "Section (general): http_out required when output_type is http",
        "Section (general): https_ssl_verify not specified defaulting to TRUE",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing custom_api_id",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("confs/invalid-tcp.toml", True, [
        "Section (general): output_format required",
        "Section (general): tcp_out required when output_type is tcp or tcp+tls",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing org_key",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("confs/invalid-udp.toml", True, [
        "Section (general): output_format required",
        "Section (general): udp_out required when output_type is udp",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing custom_api_id",
        "No valid Carbon Black Cloud instances provided"
    ])
])
def test_validate_invalid(file_path, valid, caplog, logs):
    """Test Validate with invalid configuration files"""
    resolved_path = str(FIXTURES_PATH.joinpath(file_path))
    config = Config(resolved_path)
    assert not config.validate()

    for index, record in enumerate(caplog.records):
        assert record.msg == logs[index]


@pytest.mark.parametrize("file_path, expected_params", [
    ("confs/cef.toml",
        {
            "back_up_dir": "/Users/jdoe/Documents/",
            "format": "cef",
            "template": "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}",  # noqa 501
            "type": "udp",
            "host": "0.0.0.0",
            "port": "8886"
        }),
    ("confs/json.toml",
        {
            "back_up_dir": "/Users/avanbrunt/Desktop/backdir",
            "format": "json",
            "template": None,
            "type": "http",
            "host": "http://0.0.0.0:5001/http_out",
            "port": None,
            "http_headers": {"content-type": "application/json"},
            "tls_verify": False
        }),
    ("confs/leef.toml",
        {
            "back_up_dir": "/Users/jdoe/Documents/",
            "ca_cert": "/etc/cb/integrations/cbc-syslog/ca.pem",
            "cert": "/etc/cb/integrations/cbc-syslog/cert.pem",
            "format": "leef",
            "host": "0.0.0.0",
            "key": "/etc/cb/integrations/cbc-syslog/cert.key",
            "key_password": None,
            "port": "8888",
            "template": "",
            "tls_verify": True,
            "type": "tcp+tls"})
])
def test_output(file_path, expected_params):
    """Verify output creates valid configuration dict"""
    resolved_path = str(FIXTURES_PATH.joinpath(file_path))
    config = Config(resolved_path)
    output_params = config.output()
    assert output_params == expected_params


@pytest.mark.parametrize("file_path, expected_sources", [
    ("confs/json.toml",
        [{
            "custom_api_id": "RANDOM_ID",
            "custom_api_key": "RANDOM_SECRET",
            "org_key": "SOME_ORG",
            "server_url": "http://0.0.0.0:5001",
            "alerts_enabled": False,
            "alert_rules": [{}]
        }]),
    ("confs/multi-tenant.toml",
        [{
            "custom_api_id": "RANDOM_ID",
            "custom_api_key": "RANDOM_SECRET",
            "org_key": "SOME_ORG",
            "server_url": "http://0.0.0.0:5001",
            "alerts_enabled": False,
            "alert_rules": [{}]
        }, {
            "custom_api_id": "RANDOM_ID",
            "custom_api_key": "RANDOM_SECRET",
            "org_key": "DIFFERENT_ORG",
            "server_url": "http://0.0.0.0:5001",
            "alerts_enabled": True,
            "alert_rules": [{
                "type": ["CB_ANALYTICS"],
                "minimum_severity": 3,
                "policy_applied": True
            }, {
                "type": ["WATCHLIST"],
                "minimum_severity": 7
            }]
        }]),
])
def test_sources(file_path, expected_sources):
    """Verify output creates valid configuration dict"""
    resolved_path = str(FIXTURES_PATH.joinpath(file_path))
    config = Config(resolved_path)
    sources = config.sources()
    assert sources == expected_sources
