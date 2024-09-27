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

"""Tests for the Transform object."""

from cbc_syslog import __version__
from cbc_syslog.util import Transform

from freezegun import freeze_time
from tests.fixtures.mock_alerts import CB_ANALYTICS_ALERT
from tests.fixtures.mock_audit_logs import AUDIT_LOGGED_IN


@freeze_time("2023-05-01")
def test_render_template():
    """Test render with template and no extension"""
    config = {
        "template": "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|"
                    "{{reason_code}}|{{reason}}|{{severity}}|{{extension}}"
    }

    transform = Transform(**config)
    result = transform.render(CB_ANALYTICS_ALERT)

    expected_result = f"2023-05-01T00:00:00.000000Z localhost CEF:1|CarbonBlack|CBCSyslog|{__version__}|R_NET_SERVER|" \
                      f"The application run.js acted as a network server.|3|"
    assert result == expected_result


@freeze_time("2023-05-01")
def test_render_custom_template():
    """Test render with custom template for CB Analytics alert"""
    config = {
        "template": "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|"
                    "{{reason_code}}|{{reason}}|{{severity}}|{{extension}}",
        "extension": {
            "CB_ANALYTICS": "cat={{type}}\tframeworkName=MITRE_ATT&CK\tthreatAttackID={{attack_tactic}}:{{attack_technique}}\t"
                            "act={{sensor_action}}\texternalId={{id}}\trt={{backend_timestamp}}\tstart={{first_event_timestamp}}\t"
                            "outcome={{run_state}}\tdeviceProcessId={{process_pid}}\tdeviceProcessName={{process_name}}\t"
                            "fileHash={{process_sha256}}\tdeviceExternalId={{device_id}}\tdvc={{device_internal_ip}}\t"
                            "duser={{device_username}}\tcs1={{threat_id}}\tcs1Label=Threat_ID\tcs2={{alert_url}}\tcs2Label=Link\t"
                            "cs3={{device_name}}\tcs3Label=Device_Name\tcs4={{process_effective_reputation}}\t"
                            "cs4Label=Process_Effective_Reputation\tcs5={{parent_name}}\tcs5Label=Parent_Name\tcs6={{parent_sha256}}\t"
                            "cs6Label=Parent_Hash\tc6a1={{device_external_ip}}\tc6a1Label=External_Device_Address"
        },
        "type_field": "type",
        "time_format": "%b %d %Y %H:%m:%S",
        "time_fields": ["backend_timestamp", "first_event_timestamp"]
    }
    transform = Transform(**config)
    result = transform.render(CB_ANALYTICS_ALERT)

    expected_result = f"2023-05-01T00:00:00.000000Z localhost CEF:1|CarbonBlack|CBCSyslog|{__version__}|R_NET_SERVER|" \
                      f"The application run.js acted as a network server.|3|cat=CB_ANALYTICS\tframeworkName=MITRE_ATT&CK\t" \
                      f"threatAttackID=:\tact=ALLOW\texternalId=4ef0639c-4b4f-11d1-5695-d74e9dc506ec\trt=May 03 2023 11:05:36\t" \
                      f"start=May 03 2023 11:05:24\toutcome=RAN\tdeviceProcessId=2856\t" \
                      f"deviceProcessName=c:\\program files\\logrhythm\\logrhythm common\\logrhythm api gateway\\run.js\t" \
                      f"fileHash=cb67bdbbbd4ae997204d76eae913dac7117fe3f0ef8a42a3255f64266496898b\tdeviceExternalId=6360983\t" \
                      f"dvc=10.128.65.193\tduser=shalaka.makeshwar@logrhythm.com\tcs1=1f3e23938445418af225bfbcedc33ac2\t" \
                      f"cs1Label=Threat_ID\tcs2=https://defense.conferdeploy.net/alerts?s[c][query_string]=" \
                      f"id:4ef0639c-4b4f-11d1-5695-d74e9dc506ec&orgKey=7DESJ9GN\tcs2Label=Link\tcs3=QA\\SM-2K16\t" \
                      f"cs3Label=Device_Name\tcs4=LOCAL_WHITE\tcs4Label=Process_Effective_Reputation\t" \
                      f"cs5=c:\\program files\\logrhythm\\logrhythm common\\logrhythm api gateway\\dependencies\\procman\\procman.exe\t" \
                      f"cs5Label=Parent_Name\tcs6=be3daaaa1597094a597e71ff95382afbb502dfe0c25bc1d7eb488b8ca658c69e\t" \
                      f"cs6Label=Parent_Hash\tc6a1=65.38.174.94\tc6a1Label=External_Device_Address"
    assert result == expected_result


@freeze_time("2023-05-01")
def test_render_with_invalid_type():
    """Test render with invalid type and no extension"""
    config = {
        "template": "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|"
                    "{{reason_code}}|{{reason}}|{{severity}}|{{extension}}",
        "extension": {},
        "type_field": "invalid"
    }
    transform = Transform(**config)
    result = transform.render(CB_ANALYTICS_ALERT)

    expected_result = f"2023-05-01T00:00:00.000000Z localhost CEF:1|CarbonBlack|CBCSyslog|{__version__}|R_NET_SERVER|" \
                      f"The application run.js acted as a network server.|3|"
    assert result == expected_result


@freeze_time("2023-05-01")
def test_render_with_default_fallback():
    """Test render with invalid type and no extension"""
    config = {
        "template": "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|"
                    "{{reason_code}}|{{reason}}|{{severity}}|{{extension}}",
        "extension": {
            "default": "cat={{type}}\tact={{sensor_action}}\toutcome={{run_state}}"
        },
        "type_field": "invalid"
    }
    transform = Transform(**config)
    result = transform.render(CB_ANALYTICS_ALERT)

    expected_result = f"2023-05-01T00:00:00.000000Z localhost CEF:1|CarbonBlack|CBCSyslog|{__version__}|R_NET_SERVER|" \
                      f"The application run.js acted as a network server.|3|cat=CB_ANALYTICS\tact=ALLOW\toutcome=RAN"
    assert result == expected_result


@freeze_time("2023-05-01")
def test_render_with_invalid_time_format():
    """Test render with invalid time format"""
    config = {
        "template": "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|"
                    "{{reason_code}}|{{reason}}|{{severity}}|{{extension}}",
        "extension": {
            "default": "rt={{backend_timestamp}}\tstart={{first_event_timestamp}}"
        },
        "time_format": None,
        "time_fields": ["backend_timestamp"]
    }
    transform = Transform(**config)
    result = transform.render(CB_ANALYTICS_ALERT)

    expected_result = f"2023-05-01T00:00:00.000000Z localhost CEF:1|CarbonBlack|CBCSyslog|{__version__}|R_NET_SERVER|" \
                      f"The application run.js acted as a network server.|3|rt=2023-05-03T11:18:36.184Z\tstart=2023-05-03T11:17:24.429Z"
    assert result == expected_result


@freeze_time("2023-05-01")
def test_render_custom_template_audit_log():
    """Test render with custom template for Audit Log"""
    config = {
        "template": "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}"
                    "|Audit Logs|{{description}}|1|{{extension}}",
        "extension": {
            "default": "rt={{eventTime}}\tdvchost={{orgName}}\tduser={{loginName}}\tdvc={{clientIp}}\tcs4Label=Event_ID\tcs4={{eventId}}"
        },
        "time_format": "%b %d %Y %H:%m:%S",
        "time_fields": ["eventTime"]
    }
    transform = Transform(**config)
    expected_result = f"2023-05-01T00:00:00.000000Z localhost CEF:1|CarbonBlack|CBCSyslog|{__version__}|Audit Logs|" \
                      f"Logged in successfully|1|rt=Jun 18 2018 14:06:07	dvchost=example.org	duser=bs@carbonblack.com" \
                      f"	dvc=192.0.2.3	cs4Label=Event_ID	cs4=37075c01730511e89504c9ba022c3fbf"
    assert transform.render(AUDIT_LOGGED_IN) == expected_result
