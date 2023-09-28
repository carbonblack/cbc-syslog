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

"""Tests for the Output object."""

import json
import logging
import pathlib
import pytest
import time

from io import StringIO
from freezegun import freeze_time
from tests.fixtures.mock_alerts import GET_ALERTS_BULK
from tests.fixtures.mock_audit_logs import GET_AUDIT_LOGS_BULK
from tests.fixtures.mock_stdin import (TEMPLATE_HTTP,
                                       TEMPLATE_TCP_TLS,
                                       TEMPLATE_UDP,
                                       JSON_FILE,
                                       CONVERT_UDP,
                                       CONVERT_TEMPLATE_TCP_TLS,
                                       CONVERT_TEMPLATE_HTTP)

from cbc_syslog import poll, check, history, wizard, convert
from cbc_syslog.util import Config

CONFS_PATH = pathlib.Path(__file__).joinpath("../../fixtures/confs").resolve()
TMP_PATH = pathlib.Path(__file__).joinpath("../../fixtures/tmp").resolve()
STATE_FILEPATH = pathlib.Path(__file__).joinpath("../../fixtures/tmp/cbc_syslog_state.json").resolve()


@freeze_time("2023-07-05 00:00:00")
def test_poll(wipe_tmp):
    """Test successful poll cycle"""
    config = Config(str(CONFS_PATH.joinpath("template.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    pytest.alert_search_response = GET_ALERTS_BULK(1, 1)

    poll(config)

    # Add small sleep to wait for TCP response
    time.sleep(0.1)

    assert pytest.alert_search_request["criteria"]["last_update_time"] == {
        "end": "2023-07-04T23:59:30.000000Z",
        "start": "2023-07-04T23:58:30.000000Z"
    }
    assert pytest.tcp_recv_data.decode() == "2023-07-05T00:00:00.000000Z localhost CEF:1|CarbonBlack|CBCSyslog|2.0.0|R_NET_SERVER" \
                                            "|The application run.js acted as a network server.|3|cat=CB_ANALYTICS\tact=ALLOW\t" \
                                            "outcome=RAN\tframeworkName=MITRE_ATT&CK\tthreatAttackID=:"
    assert len(pytest.recv_history) == 2

    with open(STATE_FILEPATH, "r") as state_file:
        previous_state = json.load(state_file)
        assert previous_state["end_time"] == "2023-07-04T23:59:30.000000Z"


@freeze_time("2023-07-05 00:00:00")
def test_poll_failed_org(wipe_tmp):
    """Test poll cycle with failing org"""
    config = Config(str(CONFS_PATH.joinpath("single-tenant.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    def alert_output(request):
        """Alert output callable"""
        raise Exception

    pytest.alert_search_response = alert_output

    poll(config)

    assert pytest.http_recv_data is None

    with open(STATE_FILEPATH, "r") as state_file:
        previous_state = json.load(state_file)
        assert previous_state["end_time"] == "2023-07-04T23:59:30.000000Z"
        assert previous_state["failed_orgs"]["SOME_ORG"]["alerts"] == "2023-07-04T23:58:30.000000Z"


@freeze_time("2023-07-05 00:01:00")
def test_poll_retry_failed_org(wipe_tmp):
    """Test poll cycle with previously failed org"""
    config = Config(str(CONFS_PATH.joinpath("single-tenant.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    # Write failed state
    with open(STATE_FILEPATH, "w") as state_file:
        state_file.write(json.dumps({
            "failed_orgs": {
                "SOME_ORG": {
                    "alerts": "2023-07-04T23:58:30.000000Z"
                }
            },
            "end_time": "2023-07-04T23:59:30.000000Z"
        }, indent=4))

    pytest.alert_search_response = GET_ALERTS_BULK(1, 1)

    poll(config)

    assert pytest.alert_search_request["criteria"]["last_update_time"] == {
        "end": "2023-07-05T00:00:30.000000Z",
        "start": "2023-07-04T23:58:30.000000Z"
    }

    assert json.loads(pytest.http_recv_data.decode("utf-8")) == GET_ALERTS_BULK(1, 1)["results"][0]

    with open(STATE_FILEPATH, "r") as state_file:
        previous_state = json.load(state_file)
        assert previous_state["end_time"] == "2023-07-05T00:00:30.000000Z"
        assert previous_state["failed_orgs"] == {}


@freeze_time("2023-07-05 00:01:00")
def test_poll_retry_before_30s(wipe_tmp):
    """Test retry poll cycle before 30s minimum"""
    config = Config(str(CONFS_PATH.joinpath("single-tenant.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    # Write current time state
    with open(STATE_FILEPATH, "w") as state_file:
        state_file.write(json.dumps({
            "end_time": "2023-07-05T00:01:00.000000Z"
        }, indent=4))

    assert poll(config) is False


@freeze_time("2023-07-05 00:01:00")
def test_poll_backup(wipe_tmp):
    """Test poll cycle with fail to output"""
    config = Config(str(CONFS_PATH.joinpath("bad-output.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    pytest.alert_search_response = GET_ALERTS_BULK(1, 1)

    poll(config)

    with open(STATE_FILEPATH, "r") as state_file:
        previous_state = json.load(state_file)
        assert previous_state["end_time"] == "2023-07-05T00:00:30.000000Z"

    with open(TMP_PATH.joinpath("cbc-2023-07-04T23:59:30.000000Z.bck").resolve(), "r") as backup_file:
        json_string = backup_file.readline()
        assert json.loads(json_string) == GET_ALERTS_BULK(1, 1)["results"][0]


@freeze_time("2023-07-05 00:01:00")
@pytest.mark.filterwarnings("ignore:Unverified HTTPS request.*")
def test_poll_retry_output_backup(wipe_tmp):
    """Test poll cycle with retry on backup files"""
    config = Config(str(CONFS_PATH.joinpath("single-tenant.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    pytest.alert_search_response = GET_ALERTS_BULK(1, 1)

    BACKUP_FILEPATH = TMP_PATH.joinpath("cbc-2023-07-04T23:59:30.000000Z.bck").resolve()

    with open(BACKUP_FILEPATH, "w") as backup_file:
        backup_file.write(json.dumps(GET_ALERTS_BULK(1, 1)["results"][0]))

    poll(config)

    # Check backup was successfully received
    assert len(pytest.recv_history) == 2
    assert json.loads(pytest.recv_history[0].decode("utf-8")) == GET_ALERTS_BULK(1, 1)["results"][0]

    assert BACKUP_FILEPATH.exists() is False


@freeze_time("2023-07-05 00:01:00")
def test_poll_retry_output_backup_failure(wipe_tmp):
    """Test poll cycle with retry on backup files but output fails again"""
    config = Config(str(CONFS_PATH.joinpath("bad-output.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    pytest.alert_search_response = GET_ALERTS_BULK(1, 1)

    BACKUP_FILEPATH = TMP_PATH.joinpath("cbc-2023-07-04T23:58:30.000000Z.bck").resolve()

    with open(BACKUP_FILEPATH, "w") as backup_file:
        backup_file.write(json.dumps(GET_ALERTS_BULK(1, 1)["results"][0]))

    poll(config)

    # Check of previous backup file and new backup file are created
    with open(BACKUP_FILEPATH, "r") as backup_file:
        json_string = backup_file.readline()
        assert json.loads(json_string) == GET_ALERTS_BULK(1, 1)["results"][0]

    with open(TMP_PATH.joinpath("cbc-2023-07-04T23:59:30.000000Z.bck").resolve(), "r") as backup_file:
        json_string = backup_file.readline()
        assert json.loads(json_string) == GET_ALERTS_BULK(1, 1)["results"][0]


@freeze_time("2023-07-05 00:01:00")
def test_poll_backup_dir_invalid(wipe_tmp):
    """Test poll cycle with invalid backup directory"""
    config = Config(str(CONFS_PATH.joinpath("single-tenant.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = "/invalid"

    assert poll(config) is False


@freeze_time("2023-07-05 00:01:00")
def test_poll_audit_logs(wipe_tmp):
    """Test poll cycle with only audit_logs"""
    config = Config(str(CONFS_PATH.joinpath("audit-logs-only.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    # Set Audit Log Response
    pytest.audit_log_response = GET_AUDIT_LOGS_BULK(1)

    poll(config)

    assert pytest.http_recv_data.decode("utf-8") == "2023-07-05T00:01:00.000000Z localhost " \
        "CEF:1|CarbonBlack|CBCSyslog|2.0.0|Audit Logs|Logged in successfully|1|rt=1529332687006" \
        "\tdvchost=example.org\tduser=bs@carbonblack.com\tdvc=192.0.2.3\tcs4Label=Event_ID\tcs4=37075c01730511e89504c9ba022c3fbf"


@freeze_time("2023-07-05 00:01:00")
def test_poll_alerts_and_audit_logs(wipe_tmp):
    """Test poll cycle with alerts and audit_logs"""
    config = Config(str(CONFS_PATH.joinpath("alerts-and-audit-logs.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    # Set Responses
    pytest.audit_log_response = GET_AUDIT_LOGS_BULK(1)
    pytest.alert_search_response = GET_ALERTS_BULK(1, 1)

    poll(config)

    assert json.loads(pytest.recv_history[0].decode("utf-8")) == GET_ALERTS_BULK(1, 1)["results"][0]
    assert json.loads(pytest.recv_history[1].decode("utf-8")) == GET_AUDIT_LOGS_BULK(1)["notifications"][0]


@freeze_time("2023-07-05 00:01:00")
def test_poll_audit_logs_exception(wipe_tmp):
    """Test poll cycle with audit_logs failure"""
    config = Config(str(CONFS_PATH.joinpath("audit-logs-only.toml")))

    # Overwrite backup_dir to tmp folder
    config.config["general"]["backup_dir"] = TMP_PATH

    def audit_log():
        """Audit Log output callable"""
        raise Exception

    # Set Audit Log Response
    pytest.audit_log_response = audit_log

    poll(config)

    with open(STATE_FILEPATH, "r") as state_file:
        previous_state = json.load(state_file)
        assert previous_state["end_time"] == "2023-07-05T00:00:30.000000Z"
        assert previous_state["failed_orgs"] == {"SOME_ORG": {"audit_logs": "2023-07-04T23:59:30.000000Z"}}


@pytest.mark.parametrize("toml, force, logs", [
    ("alerts-and-audit-logs.toml", True, [
        "Valid alerts permission detected for SOME_ORG",
        "Valid audit logs permission detected for SOME_ORG",
        "1 audit log(s) dropped for SOME_ORG"
    ]),
    ("alerts-and-audit-logs.toml", False, [
        "Valid alerts permission detected for SOME_ORG",
        "Audit logs skipped to avoid data loss use --force to test"
    ]),
    ("template.toml", False, [
        "Valid alerts permission detected for DIFFERENT_ORG"
    ]),
    ("audit-logs-only.toml", True, [
        "Section (audit_logs_template): type_field missing extension will only use default",
        "Valid audit logs permission detected for SOME_ORG",
        "1 audit log(s) dropped for SOME_ORG"
    ])
])
def test_check(toml, force, logs, caplog):
    """Test check function"""
    config = Config(str(CONFS_PATH.joinpath(toml)))

    pytest.alert_search_response = GET_ALERTS_BULK(1, 1)
    pytest.audit_log_response = GET_AUDIT_LOGS_BULK(1)

    caplog.set_level(logging.INFO)

    assert check(config, force=force)

    syslog_index = 0
    for record in caplog.records:
        if "cbc_syslog" not in record.name:
            continue
        assert record.msg == logs[syslog_index]
        syslog_index += 1


@pytest.mark.parametrize("error_code, logs", [
    (401, [
        "Unable to fetch alerts for SOME_ORG API key invalid",
        "Unable to fetch audit logs for SOME_ORG API key invalid"
    ]),
    (403, [
        "Unable to fetch alerts for SOME_ORG missing permission: org.alerts READ",
        "Unable to fetch audit logs for SOME_ORG missing permission: org.audits READ"
    ]),
    (404, [
        "Unable to fetch alerts for SOME_ORG due to exception: Received 404 (Object Not Found)",
        "Unable to fetch audit logs for SOME_ORG due to exception: Received 404 (Object Not Found)"
    ]),
    (500, [
        "Unable to fetch alerts for SOME_ORG due to exception: Received error code 500 from API",
        "Unable to fetch audit logs for SOME_ORG due to exception: Received error code 500 from API"
    ])
])
def test_check_errors(error_code, logs, caplog):
    """Test test function"""
    config = Config(str(CONFS_PATH.joinpath("alerts-and-audit-logs.toml")))

    pytest.alert_search_response = error_code
    pytest.audit_log_response = error_code

    caplog.set_level(logging.INFO)

    assert not check(config, force=True)

    syslog_index = 0
    for record in caplog.records:
        if "cbc_syslog" not in record.name:
            continue
        assert record.msg.startswith(logs[syslog_index]) or record.msg == logs[syslog_index]
        syslog_index += 1


def test_history():
    """Test history"""
    config = Config(str(CONFS_PATH.joinpath("single-tenant.toml")))

    def alert_output(request):
        """Alert output callable"""
        if request.get("criteria", {}).get("last_update_time", {}) != {
            "end": "2023-07-05T00:00:00.000000Z",
            "start": "2023-07-01T00:00:00.000000Z"
        }:
            pytest.fail("Request time range did not match expected start and end time")

        return GET_ALERTS_BULK(50, 50)

    pytest.alert_search_response = alert_output

    assert history(config, "2023-07-01T00:00:00.000Z", "2023-07-05T00:00:00.000Z")

    assert len(pytest.recv_history) == 50


def test_history_no_data_enabled():
    """Test history with no data enabled"""
    config = Config(str(CONFS_PATH.joinpath("json.toml")))

    def alert_output(request):
        """Alert output callable expected to not be called"""
        assert False

    pytest.alert_search_response = alert_output

    assert history(config, "2023-07-01T00:00:00.000Z", "2023-07-05T00:00:00.000Z")

    assert len(pytest.recv_history) == 0


def test_history_org_key():
    """Test history with specific org_key"""
    config = Config(str(CONFS_PATH.joinpath("template.toml")))

    pytest.alert_search_response = GET_ALERTS_BULK(1, 1)

    assert history(config, "2023-07-01T00:00:00.000Z", "2023-07-05T00:00:00.000Z", "DIFFERENT_ORG")

    # Add small sleep to wait for TCP response
    time.sleep(0.1)

    assert len(pytest.recv_history) == 2


def test_history_invalid_org_key():
    """Test history with invalid org_key"""
    config = Config(str(CONFS_PATH.joinpath("template.toml")))

    def alert_output(request):
        """Alert output callable expected to not be called"""
        assert False

    pytest.alert_search_response = alert_output

    assert history(config, "2023-07-01T00:00:00.000Z", "2023-07-05T00:00:00.000Z", "INVALID")

    assert len(pytest.recv_history) == 0


def test_history_exception():
    """Test history with exception from Carbon Black Cloud"""
    config = Config(str(CONFS_PATH.joinpath("single-tenant.toml")))

    pytest.alert_search_response = 401

    assert not history(config, "2023-07-01T00:00:00.000Z", "2023-07-05T00:00:00.000Z")

    assert len(pytest.recv_history) == 0


def test_history_bad_output():
    """Test history with bad output destination"""
    config = Config(str(CONFS_PATH.joinpath("bad-output.toml")))

    pytest.alert_search_response = GET_ALERTS_BULK(1, 1)

    assert not history(config, "2023-07-01T00:00:00.000Z", "2023-07-05T00:00:00.000Z")

    assert len(pytest.recv_history) == 0


def test_history_bad_start_time():
    """Test history with bad start_time"""
    config = Config(str(CONFS_PATH.joinpath("template.toml")))

    def alert_output(request):
        """Alert output callable expected to not be called"""
        assert False

    pytest.alert_search_response = alert_output

    assert not history(config, "2023-07-05T00:00:00.000Z", "2023-07-01T00:00:00.000Z")

    assert len(pytest.recv_history) == 0


def test_history_invalid_config():
    """Test history with bad config"""
    config = Config(str(CONFS_PATH.joinpath("invalid.toml")))

    def alert_output(request):
        """Alert output callable expected to not be called"""
        assert False

    pytest.alert_search_response = alert_output

    assert not history(config, "2023-07-05T00:00:00.000Z", "2023-07-01T00:00:00.000Z")

    assert len(pytest.recv_history) == 0


@pytest.mark.parametrize("input, valid_file", [
    (TEMPLATE_HTTP, "wizard-template-http.toml"),
    (TEMPLATE_TCP_TLS, "wizard-template-tcp-tls.toml"),
    (JSON_FILE, "wizard-json-file.toml"),
    (TEMPLATE_UDP, "wizard-template-udp.toml")])
def test_setup_wizard(input, valid_file, monkeypatch):
    """Test setup wizard"""
    monkeypatch.setattr('sys.stdin', StringIO(input))

    wizard(TMP_PATH.joinpath("config-test.toml"))

    file1 = open(TMP_PATH.joinpath("config-test.toml"), 'r')
    file2 = open(CONFS_PATH.joinpath(valid_file), 'r')

    file1_lines = file1.readlines()
    file2_lines = file2.readlines()

    for i in range(len(file1_lines)):
        if "backup_dir" in file1_lines[i] or "cert =" in file1_lines[i] or \
           "key = " in file1_lines[i] or "file_path = " in file1_lines[i]:
            continue
        assert file1_lines[i] == file2_lines[i]


@pytest.mark.parametrize("input, ini_file, valid_file", [
    (CONVERT_TEMPLATE_HTTP, "legacy_http.ini", "wizard-template-http.toml"),
    (CONVERT_TEMPLATE_TCP_TLS, "legacy_tcp_tls.ini", "wizard-template-tcp-tls.toml"),
    (CONVERT_UDP, "legacy_udp.ini", "wizard-template-udp.toml")])
def test_convert(input, ini_file, valid_file, monkeypatch):
    """Test convert"""
    monkeypatch.setattr('sys.stdin', StringIO(input))

    convert(str(CONFS_PATH.joinpath(ini_file)), TMP_PATH.joinpath("config-test.toml"))

    file1 = open(TMP_PATH.joinpath("config-test.toml"), 'r')
    file2 = open(CONFS_PATH.joinpath(valid_file), 'r')

    file1_lines = file1.readlines()
    file2_lines = file2.readlines()

    for i in range(len(file1_lines)):
        if "backup_dir" in file1_lines[i] or "cert =" in file1_lines[i] or \
           "key = " in file1_lines[i] or "file_path = " in file1_lines[i]:
            continue
        assert file1_lines[i] == file2_lines[i]
