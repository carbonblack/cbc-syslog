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

CONFS_PATH = pathlib.Path(__file__).joinpath("../../fixtures/confs").resolve()


@pytest.mark.parametrize("file_path, valid", [
    ("file_out.toml", True),
    ("json.toml", True),
    ("multi-tenant.toml", True),
    ("udp.toml", True),
    ("template.toml", True),
    ("tcp+tls.toml", True)
])
def test_validate(file_path, valid):
    """Validate supported configuration files"""
    resolved_path = str(CONFS_PATH.joinpath(file_path))
    config = Config(resolved_path)
    assert config.validate()


@pytest.mark.parametrize("file_path, logs", [
    ("invalid.toml", [
        "Section (general): back_up_dir required to save output in case of a destination failure",
        "Section (general): output_format required",
        "Section (general): output_type required",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("invalid-http.toml", [
        "Section (general): output_format required",
        "Section (general): http_out required when output_type is http",
        "Section (general): https_ssl_verify not specified defaulting to TRUE",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing custom_api_id",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("invalid-tcp.toml", [
        "Section (general): output_format required",
        "Section (general): tcp_out required when output_type is tcp or tcp+tls",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing org_key",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("invalid-udp.toml", [
        "Section (general): output_format required",
        "Section (general): udp_out required when output_type is udp",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing custom_api_id",
        "No valid Carbon Black Cloud instances provided"
    ]),
    ("invalid-file.toml", [
        "Section (general): back_up_dir required to save output in case of a destination failure",
        "Section (general): output_format required",
        "Section (general): file_path not specified and back_up_dir missing no file destination specified"
    ]),
    ("invalid-template.toml", [
        "Section (general): output_format is template but no templates provided"
    ]),
    ("invalid-header.toml", [
        "Section (alerts_template): template missing header"
    ]),
    ("invalid-extension.toml", [
        "Section (alerts_template): extension missing and referenced in header defaulting to empty string",
        "Section (alerts_template): time_format specified but no time_fields listed",
        "Carbon Black Cloud instance (CarbonBlackCloudServer): Missing custom_api_key",
        "No valid Carbon Black Cloud instances provided"
    ])
])
def test_validate_invalid(file_path, caplog, logs):
    """Test Validate with invalid configuration files"""
    resolved_path = str(CONFS_PATH.joinpath(file_path))
    config = Config(resolved_path)
    assert not config.validate()

    for index, record in enumerate(caplog.records):
        assert record.msg == logs[index]


@pytest.mark.parametrize("file_path, expected_params", [
    ("file_out.toml",
        {
            "back_up_dir": "/Users/jdoe/Documents/",
            "type": "file",
            "file_path": "/Users/jdoe/Documents/output/"
        }),
    ("json.toml",
        {
            "back_up_dir": "/Users/avanbrunt/Desktop/backdir",
            "type": "http",
            "host": "http://0.0.0.0:5001/http_out",
            "port": None,
            "http_headers": {"content-type": "application/json"},
            "tls_verify": False
        }),
    ("udp.toml",
        {
            "back_up_dir": "/Users/jdoe/Documents/",
            "type": "udp",
            "host": "0.0.0.0",
            "port": "8886"
        }),
    ("tcp+tls.toml",
        {
            "back_up_dir": "/Users/jdoe/Documents/",
            "ca_cert": "/etc/cb/integrations/cbc-syslog/ca.pem",
            "cert": "/etc/cb/integrations/cbc-syslog/cert.pem",
            "host": "0.0.0.0",
            "key": "/etc/cb/integrations/cbc-syslog/cert.key",
            "key_password": None,
            "port": "8888",
            "tls_verify": True,
            "type": "tcp+tls"
        })
])
def test_output(file_path, expected_params):
    """Verify output creates valid configuration dict"""
    resolved_path = str(CONFS_PATH.joinpath(file_path))
    config = Config(resolved_path)
    output_params = config.output()
    assert output_params == expected_params


@pytest.mark.parametrize("file_path, expected_sources", [
    ("json.toml",
        [{
            "custom_api_id": "RANDOM_ID",
            "custom_api_key": "RANDOM_SECRET",
            "org_key": "SOME_ORG",
            "server_url": "http://0.0.0.0:5001",
            "alerts_enabled": False,
            "alert_rules": [{}]
        }]),
    ("multi-tenant.toml",
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
    resolved_path = str(CONFS_PATH.joinpath(file_path))
    config = Config(resolved_path)
    sources = config.sources()
    assert sources == expected_sources


@pytest.mark.parametrize("file_path, expected_transform", [
    ("template.toml",
        {
            "format": "template",
            "header": "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|"
                      "{{reason_code}}|{{reason}}|{{severity}}|{{extension}}",
            "type_field": "type",
            "time_format": "%b %d %Y %H:%m:%S",
            "time_fields": ["backend_timestamp"],
            "extension": {
                "default": "cat={{type}}\tact={{sensor_action}}\toutcome={{run_state}}",
                "CB_ANALYTICS": "cat={{type}}\tact={{sensor_action}}\toutcome={{run_state}}\t"
                                "frameworkName=MITRE_ATT&CK\tthreatAttackID={{attack_tactic}}:{{attack_technique}}"
            }
        }),
    ("json.toml",
        {
            "format": "json"
        })
])
def test_transform(file_path, expected_transform):
    """Verify transform creates valid configuration dict"""
    resolved_path = str(CONFS_PATH.joinpath(file_path))
    config = Config(resolved_path)
    transform = config.transform("alerts")
    assert transform == expected_transform
