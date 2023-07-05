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

import pathlib
import pytest

from freezegun import freeze_time
from tests.fixtures.mock_alerts import GET_ALERTS_BULK

from cbc_syslog import poll
from cbc_syslog.util import Config


CONFS_PATH = pathlib.Path(__file__).joinpath("../../fixtures/confs").resolve()
TMP_PATH = pathlib.Path(__file__).joinpath("../../fixtures/tmp").resolve()


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
