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

"""Mock Audit Logs"""
AUDIT_LOGGED_IN = {
    "requestUrl": None,
    "eventTime": 1529332687006,
    "eventId": "37075c01730511e89504c9ba022c3fbf",
    "loginName": "bs@carbonblack.com",
    "orgName": "example.org",
    "flagged": False,
    "clientIp": "192.0.2.3",
    "verbose": False,
    "description": "Logged in successfully"
}


def GET_AUDIT_LOGS_BULK(num_logs):
    """Generate auditlog response based on num_logs"""
    return {
        "notifications": [AUDIT_LOGGED_IN for _ in range(num_logs)],
        "success": True,
        "message": "Success"
    }
