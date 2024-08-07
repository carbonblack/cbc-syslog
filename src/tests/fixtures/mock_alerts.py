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

"""Mock Alerts"""

CB_ANALYTICS_ALERT = {
    "org_key": "7DESJ9GN",
    "alert_url": "https://defense.conferdeploy.net/alerts?s[c][query_string]=id:4ef0639c-4b4f-11d1-5695-d74e9dc506ec&orgKey=7DESJ9GN",
    "id": "4ef0639c-4b4f-11d1-5695-d74e9dc506ec",
    "type": "CB_ANALYTICS",
    "backend_timestamp": "2023-05-03T11:18:36.184Z",
    "user_update_timestamp": None,
    "backend_update_timestamp": "2023-05-03T11:18:55.296Z",
    "detection_timestamp": "2023-05-03T11:18:01.698Z",
    "first_event_timestamp": "2023-05-03T11:17:24.429Z",
    "last_event_timestamp": "2023-05-03T11:17:24.957Z",
    "category": "MONITORED",
    "severity": 3,
    "reason": "The application run.js acted as a network server.",
    "reason_code": "R_NET_SERVER",
    "threat_id": "1f3e23938445418af225bfbcedc33ac2",
    "primary_event_id": "29b6d6cee9a411edb61537590c38ba2b",
    "policy_applied": "NOT_APPLIED",
    "run_state": "RAN",
    "sensor_action": "ALLOW",
    "workflow": {
        "change_timestamp": "2023-05-03T11:18:36.184Z",
        "changed_by_type": "SYSTEM",
        "changed_by": "ALERT_CREATION",
        "closure_reason": "NO_REASON",
        "status": "OPEN"
    },
    "determination": None,
    "tags": None,
    "alert_notes_present": False,
    "threat_notes_present": False,
    "is_updated": True,
    "device_id": 6360983,
    "device_name": "QA\\SM-2K16",
    "device_uem_id": "",
    "device_target_value": "MEDIUM",
    "device_policy": "default",
    "device_policy_id": 6525,
    "device_os": "WINDOWS",
    "device_os_version": "Windows Server 2016 x64",
    "device_username": "shalaka.makeshwar@logrhythm.com",
    "device_location": "OFFSITE",
    "device_external_ip": "65.38.174.94",
    "device_internal_ip": "10.128.65.193",
    "mdr_alert": False,
    "mdr_alert_notes_present": False,
    "mdr_threat_notes_present": False,
    "ttps": [
        "PORTSCAN",
        "MITRE_T1046_NETWORK_SERVICE_SCANNING",
        "NETWORK_ACCESS",
        "UNKNOWN_APP",
        "ACTIVE_SERVER"
    ],
    "attack_tactic": "",
    "attack_technique": "",
    "process_guid": "7DESJ9GN-00610f97-00000b28-00000000-1d96d3bcdd0b1db",
    "process_pid": 2856,
    "process_name": "c:\\program files\\logrhythm\\logrhythm common\\logrhythm api gateway\\run.js",
    "process_sha256": "cb67bdbbbd4ae997204d76eae913dac7117fe3f0ef8a42a3255f64266496898b",
    "process_md5": "c9a2a42d383e64b45d57bbea77cfbc8c",
    "process_effective_reputation": "LOCAL_WHITE",
    "process_reputation": "NOT_LISTED",
    "process_cmdline": ".\\dependencies\\node\\node.exe run.js",
    "process_username": "NT AUTHORITY\\SYSTEM",
    "process_signatures": [],
    "parent_guid": "7DESJ9GN-00610f97-000010d8-00000000-1d96d3b9e749e27",
    "parent_pid": 4312,
    "parent_name": "c:\\program files\\logrhythm\\logrhythm common\\logrhythm api gateway\\dependencies\\procman\\procman.exe",
    "parent_sha256": "be3daaaa1597094a597e71ff95382afbb502dfe0c25bc1d7eb488b8ca658c69e",
    "parent_md5": "",
    "parent_effective_reputation": "LOCAL_WHITE",
    "parent_reputation": "NOT_LISTED",
    "parent_cmdline": "",
    "parent_username": "NT AUTHORITY\\SYSTEM",
    "childproc_guid": "",
    "childproc_username": "",
    "childproc_cmdline": "",
    "netconn_remote_port": -56229888,
    "netconn_local_port": 891355136,
    "netconn_protocol": "",
    "netconn_remote_domain": "",
    "netconn_remote_ip": "10.128.65.193",
    "netconn_local_ip": "10.4.3.91",
    "netconn_remote_ipv4": "10.128.65.193",
    "netconn_local_ipv4": "10.4.3.91"
}


def GET_ALERTS_BULK(num_available, num_found):
    """Generate alert response based on num_available"""
    return {
        "num_found": num_found,
        "num_available": num_available,
        "results": [CB_ANALYTICS_ALERT for _ in range(num_available)]
    }


GET_ALERTS_SINGLE = GET_ALERTS_BULK(1, 1)
