
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
from cbc_sdk.platform import BaseAlert
from datetime import datetime, timedelta
import logging
import sys

log = logging.getLogger(__name__)


SSL_VERIFY_TEST_MODE = False
if "pytest" in sys.modules:
    SSL_VERIFY_TEST_MODE = True


class CarbonBlackCloud:
    """Carbon Black Cloud manager"""

    instances = []

    def __init__(self, sources):
        """
        Initialize the CarbonBlackCloud object.

        Args:
            sources (list): List of Carbon Black Cloud intances to connect and fetch data from

        Example:
            {
                "custom_api_id": "",
                "custom_api_key": "",
                "org_key": "",
                "server_url": "",
                "audit_logs_enabled": True,
                "alerts_enabled": True,
                "alert_criteria": {
                    "type": []
                }
            }
        """
        for source in sources:
            instance = {
                "api": CBCloudAPI(url=source["server_url"],
                                  org_key=source["org_key"],
                                  token=(source["custom_api_key"] + "/" + source["custom_api_id"]),
                                  integration="cbc-syslog",
                                  ssl_verify=not SSL_VERIFY_TEST_MODE),
                "alerts_enabled": source["alerts_enabled"],
                "alert_criteria": source["alert_criteria"],
                "audit_logs_enabled": source["audit_logs_enabled"]
            }
            self.instances.append(instance)

    def fetch_alerts(self, start, end):
        """
        Fetch alerts for all instances given a start and end time

        Args:
            start (datetime): The time to start fetching alerts
            end (datetime): The time to finish fetching alerts

        Returns:
            alerts (list): List of alerts
            failed_orgs (list): List of org_keys that failed to fetch alerts
        """
        alerts = []
        failed_orgs = []

        time_field = "last_update_time"
        time_format = "%Y-%m-%dT%H:%M:%S.%fZ"

        for instance in self.instances:
            cb = instance["api"]
            org_alerts = []

            try:
                # Fetch initial Alert batch
                org_alerts.extend(list(cb.select(BaseAlert)
                                         .set_time_range(time_field,
                                                         start=start.strftime(time_format),
                                                         end=end.strftime(time_format))
                                         .sort_by(time_field, "ASC")))

                # Check if 10k limit was hit and iteratively fetch remaining alerts
                #   by increasing start time to the last alert fetched
                if len(org_alerts) >= 10000:
                    last_alert = alerts[-1]
                    while True:
                        new_start = datetime.strptime(last_alert[time_field], time_format) + timedelta(milliseconds=1)
                        overflow = list(cb.select(BaseAlert)
                                          .set_time_range(time_field,
                                                          start=new_start.strftime(time_format),
                                                          end=end.strftime(time_format))
                                          .sort_by(time_field, "ASC"))

                        # Extend alert list with follow up alert batches
                        org_alerts.extend(overflow)
                        if len(overflow) >= 10000:
                            last_alert = overflow[-1]
                        else:
                            break
                alerts.extend(org_alerts)
            except:
                log.exception(f"Failed to fetch alerts (start: {start} - end: {end}) for org {cb.credentials.org_key}")
                failed_orgs.append(cb.credentials.org_key)

        return alerts, failed_orgs
