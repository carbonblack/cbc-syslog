# Carbon Black Cloud Syslog Connector

## Introduction

The Carbon Black Cloud Syslog connector lets administrators forward alerts and audit logs from their Carbon Black Cloud instance to local, on-premise systems or other cloud applications.

## Features

* Generates templated messages to support any desired syslog format or send the entire raw JSON message
* Supports multi-tenancy of one or more Carbon Black Cloud organizations into a single syslog stream
* Use local File, HTTP, TCP, encrypted (TCP over TLS), or UDP transport protocols to send data

### Requirements

The following python packages are required to use CBC Syslog

* carbon-black-cloud-sdk
* Jinja2
* psutil
* tomli >= 1.1.0; python_version < '3.11'

**Note:** _`tomli` is only required for python versions before 3.11 as tomlib has been included in the standard python library_

## Installation

You can install the Syslog Connector using either PyPI or GitHub.

### PyPI Installation

```
pip install cbc-syslog
```

### GitHub Installation

1. Clone the repository using SSH or HTTPS

        SSH
        git clone git@github.com:carbonblack/cbc-syslog.git

        HTTPS
        git clone https://github.com/carbonblack/cbc-syslog.git


2. Change to the CBC Syslog directory

        cd cbc-syslog

3. Install python package

        pip install .

### Create a Config file

**Coming Soon:** _Wizard setup command to walk through creating a config file from scratch_

1. Create a CUSTOM API key in at least one Carbon Black Cloud instance with the following permissions `org.alerts READ` and `org.audits READ`

    For more information on creating a CUSTOM API key see the [Carbon Black Cloud User Guide](https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-F3816FB5-969F-4113-80FC-03981C65F969.html)

2. Create a toml file - e.g. my-config.toml

    For a detailed breakdown of all the supported configurations see examples/cbc-syslog.toml.example

3. Create the general section

        [general]
        backup_dir = "/some/dir"
        output_type = "file/http/tcp/tcp+tls/udp"
        output_format = "json/template"

    a. Specify an absolute path in `backup_dir` to a directory where unsent messages and previous state can be saved in the case of failure

    b. Decide how you would like to send the messages in `output_type` from `file`, `http`, `tcp`, `tcp+tls` or `udp`

    c. Decide your `output_format` from  `json` or `template`


4. Based on the `output_type` you have choosen you'll need to configure one of the following output destinations

    Examples outputs

        file_path = "/some/dir"

        http_out = "https://example.com"
        http_headers =  "{ \"content-type\": \"application/json\" }"
        https_ssl_verify = true

        tcp_out = "1.2.3.5:514"

        udp_out = "1.2.3.5:514"


    a.  If you selected `tcp+tls` you'll need to configure the `tls` section based on your destination's expected certs

        [tls]
        ca_cert =
        cert =
        key =
        key_password =
        tls_verify =

5. If you choose `json` for `output_format` skip to step 6 otherwise see 4a

    Example CEF template

        [alerts_template]
        template = "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|{{reason_code}}|{{reason}}|{{severity}}|{{extension}}"
        type_field = "type"
        time_format = "%b %d %Y %H:%m:%S"
        time_fields = ["backend_timestamp"]

        [alerts_template.extension]
        default = "cat={{type}}\tact={{sensor_action}}\toutcome={{run_state}}"
        CB_ANALYTICS = "cat={{type}}\tact={{sensor_action}}\toutcome={{run_state}}\tframeworkName=MITRE_ATT&CK\tthreatAttackID={{attack_tactic}}:{{attack_technique}}"

        [audit_logs_template]
        template = "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|Audit Logs|{{description}}|1|{{extension}}"
        time_format = "%b %d %Y %H:%m:%S"
        time_fields = ["eventTime"]

        [audit_logs_template.extension]
        default = "rt={{eventTime}}\tdvchost={{orgName}}\tduser={{loginName}}\tdvc={{clientIp}}\tcs4Label=Event_ID\tcs4={{eventId}}"

    a. You'll need to create a template for each data type you plan to enable

    b. Each data template supports a base `template` along with the option to specify an `extension` which can be used customize each message based on the values of the specified `type_field`

    In the example above the `type_field` for alerts is set to `type` which enables a different extension to be selected based on the alert field `type`

    **Note:** _If a value is not specified in the extension then the default option will be used. The values are CASE_SENSITIVE_

    c. If you need to modify the format of a timestamp then you can specify a python strftime format in `time_format` as well as the `time_fields` that need to be modified

    For more information on strftime formats see https://strftime.org/

    d. See [Search Fields - Alert](https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/alert-search-fields/) for the full list of Alert fields

6. Configure one or more Carbon Black Cloud Organizations

    Example Organization

        [OrgName1]
        server_url = defense.conferdeploy.net
        org_key = ABCD1234
        custom_api_id = ABCDE12345
        custom_api_key = ABCDEFGHIKLMNO1234567890
        alerts_enabled = true
        audit_logs_enabled = true

    a. The `server_url` should match the hostname of your Carbon Black Cloud environment

    b. The `org_key` can be found on the API Access page in the Carbon Black Cloud console from step 1

    c. Use the CUSTOM API key from step 1

    d. Enable the desired data you would like to send for the organization

7. If you set `alerts_enabled` to `true` then you will need to configure one or more `alert_rules`

    Each `alert_rules` is a separate request for alerts such that you can configure custom criteria for a desired usecase. See [Search Fields - Alert](https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/alert-search-fields/) for the fields marked **Searchable**.

    Example Alert Rules

        [[OrgName1.alert_rules]]
        type = [ "WATCHLIST", "DEVICE_CONTROL" ]
        minimum_severity = 7

        [[OrgName1.alert_rules]]
        type = [ "CB_ANALYTICS" ]
        minimum_severity = 3

    The key is the alert field you want to filter by and the value is a list of values you want to filter except `minimum_severity` which is a single integer. Each value is OR'd for a key and values are AND'd across keys e.g. `type:( WATCHLIST OR DEVICE_CONTROL) AND minimum_severity: 7`

    If you want to fetch `ALL` alerts then use the following `alert_rules`

        [[OrgName1.alert_rules]]
        minimum_severity = 1


### Running cbc_syslog_forwarder

The script `cbc_syslog_forwarder` is installed into the OS bin directory for easy access from any directory

```
>>> cbc_syslog_forwarder --help
usage: cbc_syslog_forwarder [-h] [--log-file LOG_FILE] [-d] [-v] {poll,history,check} ...

positional arguments:
  {poll,history,check}  The action to be taken
    poll                Fetches data from configured sources and forwards to configured output since last poll
                        attempt
    history             Fetches data from source(s) for specified time range and forwards to configured
                        output
    check               Check config for valid API keys with correct permissions

options:
  -h, --help            show this help message and exit
  --log-file LOG_FILE, -l LOG_FILE
                        Log file location
  -d, --debug           Set log level to debug
  -v, --verbose         Set log level to info
```

The `cbc_syslog_forwarder` poll command is designed to be executed in a cronjob for continual syslog forwarding

```
5  *  *  *  * root cbc_syslog_forwarer --log-file /some/path/cbc-syslog.log poll /some/path/my-config.toml
```

### Customer Support

If you want to report an issue or request a new feature please open an issue on [GitHub](https://github.com/carbonblack/cbc-syslog/issues)

If you are struggling to setup the tool and your an existing Carbon Black Cloud customer reach out to [Support](https://www.vmware.com/support/services.html) from your product console or your sales contact. Support tickets can also be submitted through our [User Exchange community](https://community.carbonblack.com/community/resources/developer-relations).

For other helpful resources check out our contact us page https://developer.carbonblack.com/contact
