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
from cbc_syslog.util import CarbonBlackCloud
from datetime import datetime, timedelta, timezone

from tests.fixtures.mock_alerts import GET_ALERTS_SINGLE, GET_ALERTS_BULK


def test_init():
    """Test CarbonBlackCloud instance creation"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://example.com",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_criteria": {
            "type": []
        }
    }
    cbcloud = CarbonBlackCloud([source])
    assert len(cbcloud.instances) == 1
    assert cbcloud.instances[0]["audit_logs_enabled"] == source["audit_logs_enabled"]
    assert cbcloud.instances[0]["alerts_enabled"] == source["alerts_enabled"]
    assert cbcloud.instances[0]["alert_criteria"] == source["alert_criteria"]

    assert cbcloud.instances[0]["api"].credentials.url == source["server_url"]
    assert cbcloud.instances[0]["api"].credentials.org_key == source["org_key"]
    assert cbcloud.instances[0]["api"].credentials.token == (source["custom_api_key"] + "/" + source["custom_api_id"])


def test_init_multiple_sources():
    """Test CarbonBlackCloud multiple instance creation"""
    source_a = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://example.com",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_criteria": {
            "type": []
        }
    }
    source_b = {
        "custom_api_id": "CUSTOM_ID_B",
        "custom_api_key": "CUSTOM_KEY_B",
        "org_key": "ORG_KEY_B",
        "server_url": "https://example.com",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_criteria": {
            "type": []
        }
    }
    cbcloud = CarbonBlackCloud([source_a, source_b])
    assert len(cbcloud.instances) == 2


def test_fetch_alerts():
    """Test CarbonBlackCloud fetch alerts"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_criteria": {
            "type": ["CB_ANALYTICS"],
            "policy_id": [7113786],
            "minimum_severity": 3
        }
    }

    # Set Alert Response
    pytest.alert_search_response = GET_ALERTS_SINGLE

    end = datetime.now(timezone.utc) - timedelta(seconds=30)
    start = end - timedelta(minutes=5)
    cbcloud = CarbonBlackCloud([source])

    alerts, errors = cbcloud.fetch_alerts(start, end)
    assert len(alerts) == 1
    assert errors == []

    # Verify Alert Request
    assert pytest.alert_search_request["criteria"]["type"] == source["alert_criteria"]["type"]
    assert pytest.alert_search_request["criteria"]["policy_id"] == source["alert_criteria"]["policy_id"]
    assert pytest.alert_search_request["criteria"]["minimum_severity"] == source["alert_criteria"]["minimum_severity"]


def test_fetch_alerts_overflow():
    """Test CarbonBlackCloud fetch alerts with overflow 25k alerts"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_criteria": {}
    }

    num_requests = 0

    def alert_output(request):
        """Alert output callable"""
        nonlocal num_requests

        # First request for 10k results
        if num_requests == 0:
            num_requests += 1
            return GET_ALERTS_BULK(10000, 25000)
        # Second request for next 10k results
        elif num_requests == 1:
            num_requests += 1
            return GET_ALERTS_BULK(10000, 15000)
        # Third request for remaining 5k results
        elif num_requests == 2:
            num_requests += 1
            return GET_ALERTS_BULK(5000, 5000)
        else:
            pytest.fail(f"Received unexpected number of API requests: {num_requests}")

    # Set Alert Response
    pytest.alert_search_response = alert_output

    end = datetime.now(timezone.utc) - timedelta(seconds=30)
    start = end - timedelta(minutes=5)
    cbcloud = CarbonBlackCloud([source])

    alerts, errors = cbcloud.fetch_alerts(start, end)
    assert len(alerts) == 25000
    assert errors == []
