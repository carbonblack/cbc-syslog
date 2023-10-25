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

"""Tests for the Carbon Black Cloud object."""

import pytest
import logging
from cbc_syslog.util import CarbonBlackCloud
from datetime import datetime, timedelta, timezone

from tests.fixtures.mock_alerts import GET_ALERTS_SINGLE, GET_ALERTS_BULK
from tests.fixtures.mock_audit_logs import GET_AUDIT_LOGS_BULK


def test_init():
    """Test CarbonBlackCloud instance creation"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://example.com",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_rules": [{
            "type": ["CB_ANALYTICS"]
        }]
    }
    cbcloud = CarbonBlackCloud(source)
    assert cbcloud.instance["audit_logs_enabled"] == source["audit_logs_enabled"]
    assert cbcloud.instance["alerts_enabled"] == source["alerts_enabled"]
    assert cbcloud.instance["alert_rules"] == source["alert_rules"]

    assert cbcloud.instance["api"].credentials.url == source["server_url"]
    assert cbcloud.instance["api"].credentials.org_key == source["org_key"]
    assert cbcloud.instance["api"].credentials.token == (source["custom_api_key"] + "/" + source["custom_api_id"])


def test_fetch_alerts():
    """Test CarbonBlackCloud fetch alerts"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_rules": [{
            "type": ["CB_ANALYTICS"],
            "policy_id": [7113786],
            "minimum_severity": 3,
            "alert_notes_present": True,
            "threat_notes_present": True,
            "remote_is_private": False
        }]
    }

    # Set Alert Response
    pytest.alert_search_response = GET_ALERTS_SINGLE

    end = datetime.now(timezone.utc) - timedelta(seconds=30)
    start = end - timedelta(minutes=5)
    cbcloud = CarbonBlackCloud(source)

    alerts = cbcloud.fetch_alerts(start, end)
    assert len(alerts) == 1

    # Verify Alert Request
    assert pytest.alert_search_request["criteria"]["type"] == source["alert_rules"][0]["type"]
    assert pytest.alert_search_request["criteria"]["policy_id"] == source["alert_rules"][0]["policy_id"]
    assert pytest.alert_search_request["criteria"]["minimum_severity"] == source["alert_rules"][0]["minimum_severity"]
    assert pytest.alert_search_request["criteria"]["alert_notes_present"] == source["alert_rules"][0]["alert_notes_present"]
    assert pytest.alert_search_request["criteria"]["threat_notes_present"] == source["alert_rules"][0]["threat_notes_present"]
    assert pytest.alert_search_request["criteria"]["remote_is_private"] == source["alert_rules"][0]["remote_is_private"]


def test_fetch_alerts_overflow():
    """Test CarbonBlackCloud fetch alerts with overflow 25k alerts"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_rules": [{}]
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
    cbcloud = CarbonBlackCloud(source)

    alerts = cbcloud.fetch_alerts(start, end)
    assert len(alerts) == 25000


def test_fetch_alerts_multiple_rules():
    """Test CarbonBlackCloud fetch alerts with multiple alert rules"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_rules": [{
            "type": ["CB_ANALYTICS"],
            "policy_id": [7113786],
            "minimum_severity": 3
        }, {
            "type": ["WATCHLIST"],
        }]
    }

    num_requests = 0
    end = datetime.now(timezone.utc) - timedelta(seconds=30)
    start = end - timedelta(minutes=5)

    def alert_output(request):
        """Alert output callable"""
        nonlocal num_requests

        # Delete request criteria for easier comparison
        assert request["criteria"]["backend_update_timestamp"] == {
            "start": start.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "end": end.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        }
        del request["criteria"]["backend_update_timestamp"]

        # First request for alert rule 0
        if num_requests == 0:
            if request["criteria"] != source["alert_rules"][0]:
                pytest.fail(f"Received unexpected request for rule {source['alert_rules'][0]} != {request['criteria']}")
            num_requests += 1
            return GET_ALERTS_SINGLE
        # Second request for alert rule 1
        elif num_requests == 1:
            if request["criteria"] != source["alert_rules"][1]:
                pytest.fail(f"Received unexpected request for rule {source['alert_rules'][1]} != {request['criteria']}")
            num_requests += 1
            return GET_ALERTS_SINGLE
        else:
            pytest.fail(f"Received unexpected number of API requests: {num_requests}")

    # Set Alert Response
    pytest.alert_search_response = alert_output

    cbcloud = CarbonBlackCloud(source)

    alerts = cbcloud.fetch_alerts(start, end)
    assert len(alerts) == 2


def test_fetch_alerts_exception(caplog):
    """Test CarbonBlackCloud fetch alerts with unexpected response"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True,
        "alerts_enabled": True,
        "alert_rules": [{
            "type": ["WATCHLIST"],
        }]
    }

    caplog.set_level(logging.ERROR)

    def alert_output(request):
        """Alert output callable"""
        raise Exception

    # Set Alert Response
    pytest.alert_search_response = alert_output

    end = datetime.now(timezone.utc) - timedelta(seconds=30)
    start = end - timedelta(minutes=5)
    cbcloud = CarbonBlackCloud(source)

    alerts = cbcloud.fetch_alerts(start, end)
    assert alerts is None
    assert "for org ORG_KEY with rule configuration {'type': ['WATCHLIST']}" in caplog.records[0].msg


def test_fetch_audit_logs():
    """Test CarbonBlackCloud fetch audit logs"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True
    }

    # Set Alert Response
    pytest.audit_log_response = GET_AUDIT_LOGS_BULK(1)

    cbcloud = CarbonBlackCloud(source)

    audit_logs = cbcloud.fetch_audit_logs(1)
    assert len(audit_logs) == 1
    assert audit_logs[0] == GET_AUDIT_LOGS_BULK(1)["notifications"][0]


def test_fetch_audit_logs_exception():
    """Test CarbonBlackCloud fetch audit logs with failed response"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True
    }

    def audit_log():
        """Audit Log output callable"""
        raise Exception

    # Set Alert Response
    pytest.audit_log_response = audit_log

    cbcloud = CarbonBlackCloud(source)

    assert cbcloud.fetch_audit_logs(1) is None


def test_fetch_audit_logs_multiple_batches():
    """Test CarbonBlackCloud fetch audit logs"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True
    }

    # Set Alert Response
    pytest.audit_log_response = GET_AUDIT_LOGS_BULK(2500)

    cbcloud = CarbonBlackCloud(source)

    audit_logs = cbcloud.fetch_audit_logs(5)
    assert len(audit_logs) == 12500


def test_fetch_audit_logs_multiple_batches_short_circuit():
    """Test CarbonBlackCloud fetch audit logs"""
    source = {
        "custom_api_id": "CUSTOM_ID",
        "custom_api_key": "CUSTOM_KEY",
        "org_key": "ORG_KEY",
        "server_url": "https://0.0.0.0:5001",
        "audit_logs_enabled": True
    }

    num_requests = 0

    def audit_log():
        """Audit Log output callable"""
        nonlocal num_requests

        num_requests += 1
        if num_requests == 1:
            return GET_AUDIT_LOGS_BULK(1)
        else:
            pytest.fail(f"Received unexpected number of API requests: {num_requests}")

    # Set Alert Response
    pytest.audit_log_response = audit_log

    cbcloud = CarbonBlackCloud(source)

    audit_logs = cbcloud.fetch_audit_logs(5)
    assert len(audit_logs) == 1
