
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

"""Carbon Black Cloud class"""

from cbc_sdk import CBCloudAPI
from cbc_sdk.platform import Alert, AuditLog
from cbc_sdk.errors import ClientError, UnauthorizedError
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
                              ssl_verify=not SSL_VERIFY_TEST_MODE,
                              proxy=source.get("proxy", None)),
            "alerts_enabled": source.get("alerts_enabled", False),
            "alert_rules": source.get("alert_rules", []),
            "audit_logs_enabled": source.get("audit_logs_enabled", False)
        }

    def test_key(self, force=False):
        """
        Test key for permissions based on enabled data

        Args:
            force (bool): Whether to test impacting data sources e.g. Audit Logs queue

        Returns
            bool: Whether the keys succeeded
        """
        cb = self.instance["api"]
        org_key = cb.credentials.org_key

        success = True

        if self.instance["alerts_enabled"]:
            try:
                cb.select(Alert).first()
                log.info(f"Valid alerts permission detected for {org_key}")
            except ClientError as e:
                if e.error_code == 403:
                    log.error(f"Unable to fetch alerts for {org_key} missing permission: org.alerts READ")
                else:
                    log.error(f"Unable to fetch alerts for {org_key} due to exception: {e}")
                success = False
            except UnauthorizedError:
                log.error(f"Unable to fetch alerts for {org_key} API key invalid")
                success = False
            except Exception as e:
                log.error(f"Unable to fetch alerts for {org_key} due to exception: {e}")
                success = False

        if self.instance["audit_logs_enabled"]:
            if not force:
                log.info("Audit logs skipped to avoid data loss use --force to test")
            else:
                try:
                    logs = AuditLog.get_auditlogs(cb)
                    log.info(f"Valid audit logs permission detected for {org_key}")
                    log.warning(f"{len(logs)} audit log(s) dropped for {org_key}")
                except ClientError as e:
                    if e.error_code == 403:
                        log.error(f"Unable to fetch audit logs for {org_key} missing permission: org.audits READ")
                    else:
                        log.error(f"Unable to fetch audit logs for {org_key} due to exception: {e}")
                    success = False
                except UnauthorizedError:
                    log.error(f"Unable to fetch audit logs for {org_key} API key invalid")
                    success = False
                except Exception as e:
                    log.error(f"Unable to fetch audit logs for {org_key} due to exception: {e}")
                    success = False

        return success

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

        time_field = "backend_update_timestamp"
        time_format = "%Y-%m-%dT%H:%M:%S.%fZ"

        def build_query(cb, alert_rule, start, end):
            """Build CBC SDK Alert Query"""
            query = cb.select(Alert) \
                      .add_time_criteria(time_field,
                                         start=start.strftime(time_format),
                                         end=end.strftime(time_format)) \
                      .set_time_range(start=(start - timedelta(days=1)),
                                      end=(end + timedelta(days=1))) \
                      .sort_by(time_field, "ASC") \
                      .set_rows(10000)

            # Iterate criteria options
            for key in alert_rule.keys():
                # Check for custom criteria
                if key == "minimum_severity":
                    query.set_minimum_severity(alert_rule[key])

                # Changes with UAE v7 alerts
                elif key == "alert_notes_present":
                    query.set_alert_notes_present(alert_rule[key])
                elif key == "threat_notes_present":
                    query.set_threat_notes_present(alert_rule[key])
                elif key == "remote_is_private":
                    query.set_remote_is_private(alert_rule[key])

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
                rule_alerts.extend(build_query(cb, alert_rule, start, end).all())

                # Check if 10k limit was hit and iteratively fetch remaining alerts
                #   by increasing start time to the last alert fetched
                if len(rule_alerts) >= 10000:
                    last_alert = rule_alerts[-1]
                    while True:
                        new_start = datetime.strptime(last_alert[time_field], time_format) + timedelta(milliseconds=1)
                        overflow = build_query(cb, alert_rule, new_start, end)

                        # Extend alert list with follow up alert batches
                        rule_alerts.extend(overflow.all())
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
                new_logs = AuditLog.get_auditlogs(cb)
                audit_logs.extend(new_logs)
                if len(new_logs) < 2500:
                    break
        except:
            log.exception(f"Failed to fetch audit logs for org {cb.credentials.org_key}")
            return None
        return audit_logs
