
# Migration Guide

Are you a CBC Syslog 1.0 user? The following guide will help you upgrade to CBC Syslog 2.0

CBC Syslog 2.0 Features:
* Full Alert v7 support
* Alerts and Audit logs are decoupled
* Complete syslog message templating support
* Improved install experience
* Single API key per organization
* Support for all Carbon Black Cloud alert types
* Improved error handling

## Config File

The configuration file has changed from `conf` to `toml` to enable a wider configuration experience

**Differences:**
* Strings require quotes
* Supports lists of values
* Supports nested tables

For more information on the `toml` specification see https://toml.io/en/

**Property Changes:**
* `back_up_dir` renamed to `backup_dir`
* Removed `requests_ca_cert`
* `leef` and `cef` replaced with `template` for `output_format`
* `api_connector_id`, `api_key`, `siem_connector_id`, and `siem_api_key` replaced with `custom_api_id` and `custom_api_key`
* `template` moved inside `alerts_template` table
* Removed `policy_action_severity`

**Coming Soon:** `convert` command in `cbc_syslog_forwarder` to more easily migrate to the latest `toml` file structure

### Template

The changes to templating has increased the ability to customize what syslog message you want to generate. For more information see [Creating a custom message with templates](README.md#creating-a-custom-message-with-templates).

If you want to see examples of predefined templates see the sections below

#### CEF

The move from notifications to alerts has increased the number of fields which can be mapped to CEF. Given each alert type has a variety of different properties we can utilize the new customizable extensions to map the unique fields for each alert type.

Take a look at the new CEF mappings in [cef.toml.example](/examples/cef.toml.example).

**Note:** If you don't need as much data or have message size limitions then modify the templates to your desired size or adjust the mapped properties.

For more information on CEF check out the [CEF Mappings Specification](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/#CEF/Chapter%202%20ArcSight%20Extension.htm?TocPath=_____3)

#### LEEF

**NOT RECOMMENDED:** The `leef` format is not recommended instead checkout out our latest [IBM QRadar App](https://developer.carbonblack.com/reference/carbon-black-cloud/integrations/qradar-app)


If you are not using IBM QRadar please open an [issue on Github](https://github.com/carbonblack/cbc-syslog/issues) for additional support otherwise take a look at [leef.toml.example](/examples/leef.toml.example)

For more information on LEEF check out the [LEEF Mapping Specification](https://www.ibm.com/docs/en/dsm?topic=overview-predefined-leef-event-attributes)


## CBC Syslog Script

Previously CBC Syslog was executed from the python site-packages which can be a challenge to find based on your installation or operating system. With CBC Syslog 2.0, we have moved the exectuable to be installed to your operating system bin directory so that it can be executed from wherever you'd prefer.

See [Running cbc_syslog_forwarder](README.md#running-cbc_syslog_forwarder) for more information
