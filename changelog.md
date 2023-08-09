# Changelog
All notable changes to this project will be documented in this file.

## Version 2.0.0

The CBC Syslog tool has been rewritten from the ground up to provide increased customization and improved Alert data with support for the latest Carbon Black Cloud alert types

**NEW:**
* Added increased message templating support for any syslog format
    * Supports customizable extensions based on a configurable type field
    * Supports customizable timestamp format
* Audit logs and Alerts can be enabled independently
* Added new cbc_syslog_forwarder script which is installed into OS bin directory
* New CBC Syslog commands to support config validation, polling, and historical fetch for alerts
* All current and future alert types are supported by default
* Built in notification rule style support using alert_rules to configure specific filters that reduce noise and alert fatigue
* Only one API key required to fetch all Carbon Black Cloud data
* Improved configuration validation and logging

**Breaking Changes:**
* New configuration file format from conf to toml
* Moved from Carbon Black Cloud notifications to Alerts v7 schema
* Removed CEF and LEEF support for better message templating to customize to any syslog format
* back_up_dir renamed to backup_dir
* api_connector_id/api_key and siem_connector_id/siem_key renamed to custom_api_id/custom_api_key
* Removed requests_ca_cert
* Changed CLI parameters to increase functionality
* Removed dead cacert.pem
* Changed how cbc-syslog is executed to support better python practices

**Bug fixes:**
* Improved Backup Directory support to only process cbc syslog .bck files
* Improved handling for Carbon Black Cloud server_url supports hostname with https or without and removes trailing backslash

## Version 1.3.1

**General:**
* Update to latest jinja2 package

**Bug fixes:**
* Rename parser file to prevent conflict on windows
* Reformat package to move files into a util subfolder

## Version 1.3.0

**Breaking Changes:**
* Leef output has been rewritten to better utilize common properties and include as much information as possible
* Code and files have been refactored and renamed to better align with the product

**Bug fixes:**
* Config file no longer fails when output_format is leef
* Added Python 3 support with the addition of the python six package.
* Tests have been rewritten and additional tests around the config file have been added
* https_ssl_verify allows for false value

## Version 1.0.1

### Bug Fix

Removed the package fcntl and replaced it with the package psutils. This ensures multi-platform functionality for
the connector.

## Version 1.0.0

### New Installation instructions

The Syslog Connector will now be moved to a pip install. Please see README.md for more information about the
installation instructions.  The previous yum installation will be deprecated.

### Back Up Directory Feature

In the configuration file, a Backup Directory location can now be added. This allows backup files to be stored
in the case that the Connector fails to send the data to Syslog.

Please see the following example:

    backup_dir = /Users/jdoe/Documents/

> **Note**: These fields are not optional and must be present in the config file.

### API Key

In the configuration file, a API Key is now available to be added. This will allow Audit Logs to be pulled from each
server in the configuration file.

Please see the following example:

    [cbdefense1]
    api_connector_id = GO5M953111
    api_key = BYCRM7BRNSH0CXZR5V1Y3111

> **Note**: These fields are not optional and must be present in the config file. If no API Key is needed, please
leave the field blank as shown below:

    [cbdefense1]
    api_connector_id =
    api_key =


### Audit Logs

Audit Logs are now available to be pulled from the Syslog Connector. To set up the program to pull Audit Logs, please
see the API Key section above. When the Syslog Connector is executing, the program will grab the Audit Logs that have
been generated since the last time the Connector was run. The following file formats are compatible with Audit Logs:
CEF,LEEF, JSON

> **Note**: All events types will be pulled from the Syslog Connector. As of now, no additional filtering is
compatible for Audit Logs.


### ThreatHunter

ThreatHunter notifications are now available to be pulled from the Syslog Connector. To set up the Connector to pull
ThreatHunter notifications you need to add the API Key as shown below in the configuration file:


    [cbdefense1]
    siem_connector_id = UEUWR4U111
    siem_api_key = XNS5UKWZXZMCC3CYC7DFM111


The file formats that are compatible with ThreatHunter Notifications are: LEEF, CEF, JSON. Just like with Audit Logs, the
program will grab only the notifications that have been generated since the last time the Connector was run.

> **Note**: All events types will be pulled from the Syslog Connector. As of now, no additional filtering is
compatible for the ThreatHunter Notifications.
