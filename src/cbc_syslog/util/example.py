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

"""Example Templates"""

EXAMPLE_ALERT_CEF_TEMPLATE = """
[alerts_template]
template = \"{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|{{reason_code}}|{{reason}}|{{severity}}|{{extension}}\"
type_field = \"type\"
time_format = \"%b %d %Y %H:%m:%S\"
time_fields = [\"backend_timestamp\", \"first_event_timestamp\"]

[alerts_template.extension]
default = \"\"\"\\
    cat={{type}}\\tframeworkName=MITRE_ATT&CK\\tthreatAttackID={{attack_tactic}}:{{attack_technique}}\\
    \\tact={{sensor_action}}\\texternalId={{id}}\\trt={{backend_timestamp}}\\tstart={{first_event_timestamp}}\\
    \\toutcome={{run_state}}\\tdeviceProcessId={{process_pid}}\\tdeviceProcessName={{process_name}}\\
    \\tfileHash={{process_sha256}}\\tdeviceExternalId={{device_id}}\\tdvc={{device_internal_ip}}\\
    \\tduser={{device_username}}\\tcs2={{alert_url}}\\tcs2Label=Link\\tcs3={{device_name}}\\
    \\tcs3Label=Device_Name\\tcs4={{process_effective_reputation}}\\tcs4Label=Process_Effective_Reputation\\
    \\tcs5={{parent_name}}\\tcs5Label=Parent_Name\\tcs6={{parent_sha256}}\\tcs6Label=Parent_Hash\\
    \\tc6a1={{device_external_ip}}\\tc6a1Label=External_Device_Address\"\"\"
CB_ANALYTICS = \"\"\"\\
    cat={{type}}\\tframeworkName=MITRE_ATT&CK\\tthreatAttackID={{attack_tactic}}:{{attack_technique}}\\
    \\tact={{sensor_action}}\\texternalId={{id}}\\trt={{backend_timestamp}}\\tstart={{first_event_timestamp}}\\
    \\toutcome={{run_state}}\\tdeviceProcessId={{process_pid}}\\tdeviceProcessName={{process_name}}\\
    \\tfileHash={{process_sha256}}\\tdeviceExternalId={{device_id}}\\tdvc={{device_internal_ip}}\\
    \\tduser={{device_username}}\\tcs1={{threat_id}}\\tcs1Label=Threat_ID\\tcs2={{alert_url}}\\tcs2Label=Link\\
    \\tcs3={{device_name}}\\tcs3Label=Device_Name\\tcs4={{process_effective_reputation}}\\
    \\tcs4Label=Process_Effective_Reputation\\tcs5={{parent_name}}\\tcs5Label=Parent_Name\\
    \\tcs6={{parent_sha256}}\\tcs6Label=Parent_Hash\\tc6a1={{device_external_ip}}\\
    \\tc6a1Label=External_Device_Address\"\"\"
CONTAINER_RUNTIME = \"\"\"\\
    cat={{type}}\\tact={{sensor_action}}\\texternalId={{id}}\\trt={{backend_timestamp}}\\
    \\tstart={{first_event_timestamp}}\\toutcome={{run_state}}\\tdeviceExternalId={{replica_id}}\\
    \\tdestinationTranslatedPort={{netconn_remote_port}}\\tsourceTranslatedPort={{netconn_local_port}}\\
    \\tapplicationProtocol={{netconn_protocol}}\\tdestinationDnsDomain={{netconn_remote_domain}}\\
    \\tdestinationTranslatedAddress={{netconn_remote_ip}}\\tsourceTranslatedAddress={{netconn_local_ip}}\\
    \\tcs1={{threat_id}}\\tcs1Label=Threat_ID\\tcs2={{alert_url}}\\tcs2Label=Link\\tcs3={{cluster}}\\
    \\tcs3Label=Cluster\\tcs4={{namespace}}\\tcs4Label=Namespace\\tcs5={{workload_kind}}\\
    \\tcs5Label=Workload_Kind\\tcs6={{remote_replica_id}}\\tcs6Label=Remote_Replica_id\"\"\"
DEVICE_CONTROL = \"\"\"\\
    cat={{type}}\\tact={{sensor_action}}\\texternalId={{id}}\\trt={{backend_timestamp}}\\
    \\tstart={{first_event_timestamp}}\\toutcome={{run_state}}\\tdeviceExternalId={{device_id}}\\
    \\tdvc={{device_internal_ip}}\\tduser={{device_username}}\\tcs1={{threat_id}}\\tcs1Label=Threat_ID\\
    \\tcs2={{alert_url}}\\tcs2Label=Link\\tcs3={{device_name}}\\tcs3Label=Device_Name\\tcs4={{vendor_id}}\\
    \\tcs4Label=Vendor_ID\\tcs5={{product_id}}\\tcs5Label=Product_ID\\tcs6={{serial_number}}\\
    \\tcs6Label=Serial_Number\\tc6a1={{device_external_ip}}\\tc6a1Label=External_Device_Address\"\"\"
HOST_BASED_FIREWALL = \"\"\"\\
    cat={{type}}\\tact={{sensor_action}}\\texternalId={{id}}\\trt={{backend_timestamp}}\\
    \\tstart={{first_event_timestamp}}\\toutcome={{run_state}}\\tdeviceProcessId={{process_pid}}\\
    \\tdeviceProcessName={{process_name}}\\tfileHash={{process_sha256}}\\tdeviceExternalId={{device_id}}\\
    \\tdvc={{device_internal_ip}}\\tduser={{device_username}}\\tdestinationTranslatedPort={{netconn_remote_port}}\\
    \\tsourceTranslatedPort={{netconn_local_port}}\\tapplicationProtocol={{netconn_protocol}}\\
    \\tdestinationDnsDomain={{netconn_remote_domain}}\\tdestinationTranslatedAddress={{netconn_remote_ip}}\\
    \\tsourceTranslatedAddress={{netconn_local_ip}}\\tcs1={{threat_id}}\\tcs1Label=Threat_ID\\tcs2={{alert_url}}\\
    \\tcs2Label=Link\\tcs3={{device_name}}\\tcs3Label=Device_Name\\tcs4={{process_effective_reputation}}\\
    \\tcs4Label=Process_Effective_Reputation\\tcs5={{parent_name}}\\tcs5Label=Parent_Name\\tcs6={{parent_sha256}}\\
    \\tcs6Label=Parent_Hash\\tc6a1={{device_external_ip}}\\tc6a1Label=External_Device_Address\"\"\"
INTRUSION_DETECTION_SYSTEM = \"\"\"\\
    cat={{type}}\\tframeworkName=MITRE_ATT&CK\\tthreatAttackID={{attack_tactic}}:{{attack_technique}}\\
    \\tact={{sensor_action}}\\texternalId={{id}}\\trt={{backend_timestamp}}\\tstart={{first_event_timestamp}}\\
    \\toutcome={{run_state}}\\tdeviceProcessId={{process_pid}}\\tdeviceProcessName={{process_name}}\\
    \\tfileHash={{process_sha256}}\\tdeviceExternalId={{device_id}}\\tdvc={{device_internal_ip}}\\
    \\tduser={{device_username}}\\tdestinationTranslatedPort={{netconn_remote_port}}\\
    \\tsourceTranslatedPort={{netconn_local_port}}\\tapplicationProtocol={{netconn_protocol}}\\
    \\tdestinationDnsDomain={{netconn_remote_domain}}\\tdestinationTranslatedAddress={{netconn_remote_ip}}\\
    \\tsourceTranslatedAddress={{netconn_local_ip}}\\tcs1={{threat_id}}\\tcs1Label=Threat_ID\\
    \\tcs2={{alert_url}}\\tcs2Label=Link\\tcs3={{device_name}}\\tcs3Label=Device_Name\\
    \\tcs4={{process_effective_reputation}}\\tcs4Label=Process_Effective_Reputation\\
    \\tcs5={{parent_name}}\\tcs5Label=Parent_Name\\tcs6={{parent_sha256}}\\tcs6Label=Parent_Hash\\
    \\tc6a1={{device_external_ip}}\\tc6a1Label=External_Device_Address\"\"\"
WATCHLIST = \"\"\"\\
    cat={{type}}\\tframeworkName=MITRE_ATT&CK\\tthreatAttackID={{attack_tactic}}:{{attack_technique}}\\
    \\tact={{sensor_action}}\\texternalId={{id}}\\trt={{backend_timestamp}}\\tstart={{first_event_timestamp}}\\
    \\toutcome={{run_state}}\\tdeviceProcessId={{process_pid}}\\tdeviceProcessName={{process_name}}\\
    \\tfileHash={{process_sha256}}\\tdeviceExternalId={{device_id}}\\tdvc={{device_internal_ip}}\\
    \\tduser={{device_username}}\\tcs1={{threat_id}}\\tcs1Label=Threat_ID\\tcs2={{alert_url}}\\
    \\tcs2Label=Link\\tcs3={{device_name}}\\tcs3Label=Device_Name\\tcs4={{process_effective_reputation}}\\
    \\tcs4Label=Process_Effective_Reputation\\tcs5={{parent_name}}\\tcs5Label=Parent_Name\\
    \\tcs6={{parent_sha256}}\\tcs6Label=Parent_Hash\\tc6a1={{device_external_ip}}\\
    \\tc6a1Label=External_Device_Address\"\"\"
"""

EXAMPLE_ALERT_LEEF_TEMPLATE = """
[alerts_template]
template = \"{{datetime_utc}} localhost LEEF:2.0|{{vendor}}|{{product}}|{{product_version}}|x09|{{extension}}\"
type_field = \"type\"
time_format = \"%b-%d-%Y %H:%M:%S GMT\"
time_fields = [\"backend_timestamp\"]

[alerts_template.extension]
default = \"\"\"\\
    cat={{type}}\\tdevTime={{backend_timestamp}}\\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\\tsev={{severity}}\\
    \\tidentSrc={{device_external_ip}}\\tresource={{device_name}}\\tpolicy={{device_policy}}\\tusrName={{device_username}}\"\"\"
"""

EXAMPLE_AUDIT_CEF_TEMPLATE = """
[audit_logs_template]
template = \"{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|Audit Logs|{{description}}|1|{{extension}}\"
type_field = \"\"
time_format = \"%b %d %Y %H:%m:%S\"
time_fields = [\"eventTime\"]

[audit_logs_template.extension]
default = \"rt={{eventTime}}\\tdvchost={{orgName}}\\tduser={{loginName}}\\tdvc={{clientIp}}\\tcs4Label=Event_ID\\tcs4={{eventId}}\"
"""

EXAMPLE_AUDIT_LEEF_TEMPLATE = """
[audit_logs_template]
template = \"{{datetime_utc}} localhost LEEF:2.0|{{vendor}}|{{product}}|{{product_version}}|Audit|x09|{{extension}}\"
type_field = \"\"
time_format = \"%b-%d-%Y %H:%M:%S GMT\"
time_fields = [\"eventTime\"]

[audit_logs_template.extension]
default = \"devTime={{eventTime}}\\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\\tusrName={{{{loginName}}}}\\tidentSrc={{clientIp}}\"
"""

EXAMPLE_ALERT_TEMPLATE = """
[alerts_template]
template =
type_field =
time_format =
time_fields =

[alerts_template.extension]
default =
"""

EXAMPLE_AUDIT_TEMPLATE = """
[audit_logs_template]
template =
type_field =
time_format =
time_fields =

[audit_logs_template.extension]
default =
"""
