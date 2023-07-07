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
import pathlib
import pytest

from freezegun import freeze_time
from tests.fixtures.mock_alerts import GET_ALERTS_BULK

from cbc_syslog import poll
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
    """Test successful poll cycle"""
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
    """Test successful poll cycle"""
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
