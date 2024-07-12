# Carbon Black Cloud Syslog Connector 2.x

## Introduction

The Carbon Black Cloud Syslog connector lets administrators forward alerts and audit logs from their Carbon Black Cloud instance to local, on-premise systems or other cloud applications.

Still need CBC Syslog 1.x? Checkout the `legacy` branch

If you are looking to migrate from CBC Syslog 1.x to 2.x take a look at the [migration doc](https://github.com/carbonblack/cbc-syslog/blob/main/MIGRATION.md).

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

You can install the Syslog Connector using either [PyPI](https://pypi.org/project/cbc-syslog) or GitHub.

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


### Running cbc_syslog_forwarder

The script `cbc_syslog_forwarder` is installed into the OS bin directory for easy access from any directory

```
>>> cbc_syslog_forwarder --help
usage: cbc_syslog_forwarder [-h] [--log-file LOG_FILE] [-d] [-v] {poll,history,convert,setup,check} ...

positional arguments:
  {poll,history,convert,setup,check}
                        The action to be taken
    poll                Fetches data from configured sources and forwards to configured output since last poll attempt
    history             Fetches data from specified source for specified time range and forwards to configured output
    convert             Convert CBC Syslog 1.0 conf to new 2.0 toml
    setup               Setup wizard to walkthrough configuration
    check               Check config for valid API keys with correct permissions

options:
  -h, --help            show this help message and exit
  --log-file LOG_FILE, -l LOG_FILE
                        Log file location
  -d, --debug           Set log level to debug
  -v, --verbose         Set log level to info
```

The `cbc_syslog_forwarder` poll command is designed to be executed in a cronjob or scheduled task for continual syslog forwarding

**Mac/Linux:**

Create a file to save the cronjob such as `syslog-job.txt`. Cronjobs use the [UNIX cron format](https://www.tutorialspoint.com/unix_commands/crontab.htm) for specifying the schedule for the job to be executed

```
5  *  *  *  *  cbc_syslog_forwarder --log-file /some/path/cbc-syslog.log poll /some/path/my-config.toml
```

To start the job once the file is created run the following command

```
crontab syslog-job.txt
```

**Windows:**

Windows uses Task Scheduler for running scheduled applications.

1. Search for **Task Scheduler**
2. Click on **Action** then **Create Task**
3. Name your Scheduled Task
5. Click on the **Actions** Tab and Click **New**
6. Under **Program/script** enter `cbc_syslog_forwarder`.
7. Under **Add arguments** provide the arguments you use to run the poll command with absolute paths to any files
8. Click OK
9. Click on the **Triggers** tab and Click **New**
10. Now is the time to schedule your Task. Fill out the information as needed and Click Ok


Your Task has been created! To test your Scheduled Task, follow these instructions below:

1. Search for Task Scheduler
2. Click on the folder **Task Scheduler Library** on the left hand column
3. Select the Task you want to Test
4. Select **Run** on the Actions column on the right hand column.

For more information on windows task scheduler checkout [how-create-automated-task-using-task-scheduler](https://www.windowscentral.com/how-create-automated-task-using-task-scheduler-windows-10)

### Create a Config file

If you are creating a CBC Syslog toml file for the first time checkout the setup wizard which walks you through the basic configuration steps.

    cbc_syslog_forwarder setup my-config.toml

For more information on each section follow the guide below:

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

        [SourceName1]
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

    e. Optionally: Add a proxy server to route Carbon Black Cloud backend requests through `proxy = "0.0.0.0:8889"`

7. If you set `alerts_enabled` to `true` then you will need to configure one or more `alert_rules`

    Each `alert_rules` is a separate request for alerts such that you can configure custom criteria for a desired usecase. See [Search Fields - Alert](https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/alert-search-fields/) for the fields marked **Searchable**.

    Example Alert Rules

        [[SourceName1.alert_rules]]
        type = [ "WATCHLIST", "DEVICE_CONTROL" ]
        minimum_severity = 7

        [[SourceName1.alert_rules]]
        type = [ "CB_ANALYTICS" ]
        minimum_severity = 3

    The key is the alert field you want to filter by and the value is a list of values you want to filter except `minimum_severity` which is a single integer. Each value is OR'd for a key and values are AND'd across keys e.g. `type:( WATCHLIST OR DEVICE_CONTROL) AND minimum_severity: 7`

    If you want to fetch `ALL` alerts then use the following `alert_rules`

        [[SourceName1.alert_rules]]
        minimum_severity = 1


### Creating a custom message with templates

The configuration file provides the ability to define a template for each data type as well as the ability to create a custom extension which can be defined based on a configurable field to make a unique message for a data's sub type

The templates use jinja2 for rendering customizable messages. You can provide the text to be included as well as variable data by wrapping the field name in double curly braces e.g. `{{field_name}}`.

#### Template Configuration Properties

* `template` defines the base syslog header which will be included for all messages of the data type

    **Note:** _Make sure to include `{{extension}}` inside the `template` value in order for the extension template to be rendered as part of the message_

* `type_field` defines the field in the data that should be used to define which extension should be rendered. The value in the extensions are case sensistive

* `time_format` and `time_fields` provides you the ability to customize the way the timestamps are formatte and which fields to modify. This utilizes python strftime formatting, for more information on strftime formats see https://strftime.org/

Example:
```
[alerts_template]
template = "{{datetime_utc}} localhost CEF:1|{{vendor}}|{{product}}|{{product_version}}|{{reason_code}}|{{reason}}|{{severity}}|{{extension}}"
type_field = "type"
time_format = "%b %d %Y %H:%m:%S"
time_fields = ["backend_timestamp"]
```

#### Extension

* `default` defines the extension which will be utilized if no field is specified for `type_field` or a value was not specified in the extension
* Any other key in the extension dictionary will be interpretted as a possible value to be matched for the `type_field`. The values are case sensistive

Example:
```
[alerts_template.extension]
default = "cat={{type}}\tact={{sensor_action}}\toutcome={{run_state}}"
CB_ANALYTICS = "cat={{type}}\tact={{sensor_action}}\toutcome={{run_state}}\tframeworkName=MITRE_ATT&CK\tthreatAttackID={{attack_tactic}}:{{attack_technique}}"
```

#### Fields

The following fields are available for building the Syslog header

* `{{datetime_utc}}` - Uses current time with format e.g. 1985-04-12T23:20:50.52Z
* `{{datetime_legacy}}` - Uses current time with format e.g. Jan 18 11:07:53
* `{{vendor}}` - CarbonBlack
* `{{product}}` - CBCSyslog
* `{{product_version}}` - Current CBC Syslog version e.g. 2.0.5


For the available Alert fields see [Search Fields - Alerts](https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/alert-search-fields)

For the available Audit Log fields see [Audit Log Events](https://developer.carbonblack.com/reference/carbon-black-cloud/cb-defense/latest/rest-api#audit-log-events)

### Customer Support

If you want to report an issue or request a new feature please open an issue on [GitHub](https://github.com/carbonblack/cbc-syslog/issues)

If you are struggling to setup the tool and your an existing Carbon Black Cloud customer reach out to [Support](https://www.vmware.com/support/services.html) from your product console or your sales contact. Support tickets can also be submitted through our [User Exchange community](https://community.carbonblack.com/community/resources/developer-relations).

For other helpful resources check out our contact us page https://developer.carbonblack.com/contact
