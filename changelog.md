# Changelog
All notable changes to this project will be documented in this file.


##2019-12-06
###SIEM Key

In the configuration file, a SIEM Key is now available to be added. This will allow Audit Logs to be pulled from each 
server in the configuration file. 

Please see the following example:

``

    [cbdefense1]
    siem_connector_id = UEUWR4U111
    siem_api_key = XNS5UKWZXZMCC3CYC7DFM111

``

NOTE: These fields are not optional and must be present in the config file. If no SIEM Key is needed, please 
leave the field blank as shown below:


`` 

    [cbdefense1]
    siem_connector_id =
    siem_api_key = 

``

### Audit Logs

Audit Logs are now available to be pulled from the Syslog Connector. To set up the program to pull Audit Logs, please 
see the SIEM Key section above. When the Syslog Connector is executing, the program will grab the Audit Logs all new 
Audit Logs since the last time the Connector was run. The following file formats are compatible with Audit Logs: CEF,
LEEF, JSON

NOTE: All events types will be pulled from the Syslog Connector. As of now, no additional filtering is 
compatible for the Audit Logs.

### ThreatHunter

ThreatHunter notifications are now available to be pulled from the Syslog Connector. To set up the Connector to pull 
ThreatHunter notifications you need to add the API Key as shown below into the configuration file: 

``

    [cbdefense1]
    api_connector_id = GO5M953111
    api_key = BYCRM7BRNSH0CXZR5V1Y3111

``

The file formats are compatible with ThreatHunter Notifications are: LEEF, CEF, JSON. Just like with Audit Logs, the 
program will grab the only the notifications that have been generated since the last time the Connector was run. 

NOTE: All events types will be pulled from the Syslog Connector. As of now, no additional filtering is 
compatible for the ThreatHunter Notifications.




