
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

"""Carbon Black Cloud class"""

from cbc_sdk import CBCloudAPI
from cbc_sdk.platform import BaseAlert  # Re-add when CBC SDK is released AuditLog
from datetime import datetime, timedelta

import logging
import sys

log = logging.getLogger(__name__)


SSL_VERIFY_TEST_MODE = False
if "pytest" in sys.modules:
    SSL_VERIFY_TEST_MODE = True


class CarbonBlackCloud:
    """Carbon Black Cloud manager"""

    def __init__(self, source):
        """
        Initialize the CarbonBlackCloud object.

        Args:
            source (dict): Carbon Black Cloud intance to connect and fetch data from

        Example:
            {
                "custom_api_id": "",
                "custom_api_key": "",
                "org_key": "",
                "server_url": "",
                "audit_logs_enabled": True,
                "alerts_enabled": True,
                "alert_rules": [
                    {
                        "type": [
                            "CB_ANALYTICS",
                            "WATCHLIST",
                            "DEVICE_CONTROL",
                            "CONTAINER_RUNTIME",
                            "HOST_BASED_FIREWALL",
                            "IDS",
                            "NTA"
                        ],
                        "minimum_severity": 1-10,
                        "policy_id": [],

                        # Watchlist Alerts
                        "watchlist_id": [],

                        # CB Analytics
                        "policy_applied": True/False,
                        "ttps": [],

                        # Not Recommended OBSERVED only applies to CB_ANALYTICS
                        "category": ["THREAT", "OBSERVED"]

                        # Support any property with key and list of values
                        "key": ["values"]

                        e.g. "device_os": ["WINDOWS", "MAC"]
                    }
                ]
            }
        """
        from .. import __version__

        self.instance = {
            "api": CBCloudAPI(url=source["server_url"],
                              org_key=source["org_key"],
                              token=(source["custom_api_key"] + "/" + source["custom_api_id"]),
                              integration_name=f"CBC_SYSLOG/{__version__}",
                              ssl_verify=not SSL_VERIFY_TEST_MODE),
            "alerts_enabled": source.get("alerts_enabled", False),
            "alert_rules": source.get("alert_rules", []),
            "audit_logs_enabled": source.get("audit_logs_enabled", False)
        }

    def fetch_alerts(self, start, end):
        """
        Fetch alerts for a specified start and end time

        Args:
            start (datetime): The time to start fetching alerts
            end (datetime): The time to finish fetching alerts

        Returns:
            alerts (list): List of alerts or None if exception raised
        """
        all_alerts = []
        failed = False

        time_field = "last_update_time"
        time_format = "%Y-%m-%dT%H:%M:%S.%fZ"

        def build_query(cb, alert_rule, start, end):
            """Build CBC SDK Alert Query"""
            query = cb.select(BaseAlert) \
                      .set_time_range(time_field,
                                      start=start.strftime(time_format),
                                      end=end.strftime(time_format)) \
                      .sort_by(time_field, "ASC")

            # Iterate criteria options
            for key in alert_rule.keys():
                # Check for custom criteria
                if key == "minimum_severity":
                    query.set_minimum_severity(alert_rule[key])

                # Changes with UAE v7 alerts
                elif key == "policy_applied":
                    continue
                    # TODO: query.set_policy_applied(alert_rule[key])

                # Add standard list value criteria
                else:
                    query.add_criteria(key, alert_rule[key])

            return query

        # Get CBCloudAPI object for instance
        cb = self.instance["api"]

        # Perform alert fetch for each alert rule
        for alert_rule in self.instance["alert_rules"]:
            rule_alerts = []

            try:
                # Fetch initial Alert batch
                rule_alerts.extend(build_query(cb, alert_rule, start, end)[0:10000])

                # Check if 10k limit was hit and iteratively fetch remaining alerts
                #   by increasing start time to the last alert fetched
                if len(rule_alerts) >= 10000:
                    last_alert = rule_alerts[-1]
                    while True:
                        new_start = datetime.strptime(last_alert[time_field], time_format) + timedelta(milliseconds=1)
                        overflow = build_query(cb, alert_rule, new_start, end)

                        # Extend alert list with follow up alert batches
                        rule_alerts.extend(overflow[0:10000])
                        if len(overflow) >= 10000:
                            last_alert = rule_alerts[-1]
                        else:
                            break
                all_alerts.extend(rule_alerts)
            except:
                log.exception(f"Failed to fetch alerts (start: {start} - end: {end})"
                              f" for org {cb.credentials.org_key} with rule configuration {alert_rule}")
                failed = True

        if failed:
            all_alerts = None
        return all_alerts

    def fetch_audit_logs(self, batches):
        """
        Fetch the next batch of audit logs

        Args:
            batches (int): The number of batches to fetch. Limit to prevent memory issues

        Returns:
            audit_logs (list): List of audit_logs or None if exception raised
        """
        cb = self.instance["api"]

        audit_logs = []
        try:
            for i in range(batches):
                # new_logs = AuditLog.get_auditlogs(cb)
                new_logs = cb.get_auditlogs()
                audit_logs.extend(new_logs)
                if len(new_logs) < 2500:
                    break
        except:
            log.exception(f"Failed to fetch audit logs for org {cb.credentials.org_key}")
            return None
        return audit_logs
