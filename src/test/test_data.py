# -*- coding: utf-8 -*-

null = ""
true = "true"
false = "false"

raw_notifications = {
    "notifications": [{
        "threatInfo": {
            "incidentId": "Z7NG6",
            "score": 7,
            "summary": "A known virus (Sality: Keylogger, Password or Data stealer, Backdoor) was detected running.",
            "indicators": [{
                "indicatorName": "PACKED_CALL",
                "applicationName": "ShippingInvoice.pdf.exe",
                "sha256Hash": "cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc"
            },
                {
                "indicatorName": "TARGET_MALWARE_APP",
                "applicationName": "explorer.exe",
                "sha256Hash": "1e675cb7df214172f7eb0497f7275556038a0d09c6e5a3e6862c5e26885ef455"
            },
                {
                "indicatorName": "HAS_PACKED_CODE",
                "applicationName": "ShippingInvoice.pdf.exe",
                "sha256Hash": "cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc"
            },
                {
                "indicatorName": "KNOWN_DOWNLOADER",
                "applicationName": "ShippingInvoice.pdf.exe",
                "sha256Hash": "cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc"
            },
                {
                "indicatorName": "ENUMERATE_PROCESSES",
                "applicationName": "ShippingInvoice.pdf.exe",
                "sha256Hash": "cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc"
            },
                {
                "indicatorName": "SET_SYSTEM_SECURITY",
                "applicationName": "ShippingInvoice.pdf.exe",
                "sha256Hash": "cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc"
            },
                {
                "indicatorName": "MODIFY_MEMORY_PROTECTION",
                "applicationName": "ShippingInvoice.pdf.exe",
                "sha256Hash": "cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc"
            },
                {
                "indicatorName": "KNOWN_PASSWORD_STEALER",
                "applicationName": "ShippingInvoice.pdf.exe",
                "sha256Hash": "cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc"
            },
                {
                "indicatorName": "RUN_MALWARE_APP",
                "applicationName": "explorer.exe",
                "sha256Hash": "1e675cb7df214172f7eb0497f7275556038a0d09c6e5a3e6862c5e26885ef455"
            },
                {
                "indicatorName": "MODIFY_PROCESS",
                "applicationName": "ShippingInvoice.pdf.exe",
                "sha256Hash": "cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc"
            },
                {
                "indicatorName": "MALWARE_APP",
                "applicationName": "ShippingInvoice.pdf.exe",
                "sha256Hash": "cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc"
            }
            ],
            "time": 1460703240678
        },
        "url": "https://testserver.company.net/ui#investigate/events/device/2004118/incident/Z7NG6",
        "eventTime": 1460703240678,
        "eventId": "f279d0e6035211e6be8701df2c083974",
        "eventDescription": "[syslog alert] [Cb Defense has detected a threat against your company.] [https://testserver.company.net/ui#device/2004118/incident/Z7NG6] [A known virus (Sality: Keylogger, Password or Data stealer, Backdoor) was detected running.] [Incident id: Z7NG6] [Threat score: 7] [Group: default] [Email: FirstName.LastName@company.net.demo] [Name: Demo_CaretoPC] [Type and OS: WINDOWS XP x86 SP: 0]\n",
        "deviceInfo": {
            "email": "COMPANY\\FirstName.LastName",
            "groupName": "default",
            "internalIpAddress": null,
            "externalIpAddress": null,
            "deviceType": "WINDOWS",
            "deviceVersion": "XP x86 SP: 0",
            "targetPriorityType": "MEDIUM",
            "deviceId": 2004118,
            "deviceName": "COMPANY\\Demo_CaretoPC",
            "deviceHostName": null,
            "targetPriorityCode": 0
        },
        "ruleName": "syslog alert",
        "type": "THREAT"
    },
    {
            "policyAction": {
                "sha256Hash": "2552332222112552332222112552332222112552332222112552332222112552",
                "action": "TERMINATE",
                "reputation": "KNOWN_MALWARE",
                "applicationName": "firefox.exe"
            },
            "type": "POLICY_ACTION",
            "eventTime": 1423163263482,
            "eventId": "EV1",
            "url": "http://carbonblack.com/ui#device/100/hash/2552332222112552332222112552332222112552332222112552332222112552/app/firefox.exe/keyword/terminate policy action",
            "deviceInfo": {
                "deviceType": "WINDOWS",
                "email": "tester@carbonblack.com",
                "deviceId": 100,
                "deviceName": "testers-pc",
                "deviceHostName": null,
                "deviceVersion": "7 SP1",
                "targetPriorityType": "HIGH",
                "targetPriorityCode": 0,
                "internalIpAddress": "55.33.22.11",
                "groupName": "Executives",
                "externalIpAddress": "255.233.222.211"
            },
            "eventDescription": "Policy action 1",
            "ruleName": "Alert Rule 1"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660",
                "score": 1,
                "summary": "PowerShell - File and Directory Discovery Enumeration",
                "time": 1554652050250,
                "indicators": [
                    {
                        "applicationName": "powershell.exe",
                        "sha256Hash": "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436",
                        "indicatorName": "565660-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "a3xW2ZiaRyAqRtuVES8Q",
                        "name": "ATT&CK Framework",
                        "alert": true
                    }
                ],
                "iocId": "565660-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "7a9fQEsTRfuFmXcogI8CMQ",
                "firstActivityTime": 1554651811577,
                "md5": "097ce5761c89434367598b34fe32893b",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf",
                "processPath": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                "reportName": "PowerShell - File and Directory Discovery Enumeration",
                "reportId": "j0MkcneCQXy1fIbhber6rw-565660",
                "reputation": "TRUSTED_WHITE_LIST",
                "responseAlarmId": "WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660",
                "responseSeverity": 1,
                "runState": "RAN",
                "sha256": "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "TRUSTED_WHITE_LIST",
                    "actor": "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436",
                    "actorName": "powershell.exe",
                    "reason": "Process powershell.exe was detected by the report \"PowerShell - File and Directory Discovery Enumeration\" in watchlist \"ATT&CK Framework\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "a2b724aa094af97c06c758d325240460",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660] [PowerShell - File and Directory Discovery Enumeration] [Incident id: WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660] [Threat score: 1] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 1]\n",
            "eventTime": 1554651811577,
            "deviceInfo": {
                "deviceId": 18900,
                "targetPriorityCode": 0,
                "groupName": "sm-detection",
                "deviceName": "win-559j1nqvfgj",
                "deviceType": "WINDOWS",
                "email": "smultani@carbonblack.com",
                "deviceHostName": null,
                "deviceVersion": "pscr-sensor",
                "targetPriorityType": "MEDIUM",
                "uemId": null,
                "internalIpAddress": "192.168.81.148",
                "externalIpAddress": "73.69.152.214"
            },
            "url": "https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660",
            "ruleName": "sm-sentinel-notification",
            "type": "THREAT_HUNTER"
        }],
    "success": true,
    "message": "Success"
}

cef_notifications = ['test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Active_Threat|A known virus (Sality: Keylogger, Password or Data stealer, Backdoor) was detected running.|7|rt="Apr 15 2016 06:54:00" sntdom=COMPANY dvchost=Demo_CaretoPC duser=FirstName.LastName dvc= cs3Label="Link" cs3="https://testserver.company.net/ui#investigate/events/device/2004118/incident/Z7NG6" cs4Label="Threat_ID" cs4="Z7NG6" act=Alert', 'test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Policy_Action|Confer Sensor Policy Action|1|rt="Feb 05 2015 19:07:43" dvchost=testers-pc duser=tester@carbonblack.com dvc=55.33.22.11 cs3Label="Link" cs3="http://carbonblack.com/ui#device/100/hash/2552332222112552332222112552332222112552332222112552332222112552/app/firefox.exe/keyword/terminate policy action" act=TERMINATE hash=2552332222112552332222112552332222112552332222112552332222112552 deviceprocessname=firefox.exe', 'test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|PowerShell - File and Directory Discovery Enumeration|1|rt="Apr 07 2019 15:43:31" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660" hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436']

leef_notifications = ['LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=ShippingInvoice.pdf.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=PACKED_CALL\tsev=Z7NG6\tsha256Hash=cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=explorer.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=TARGET_MALWARE_APP\tsev=Z7NG6\tsha256Hash=1e675cb7df214172f7eb0497f7275556038a0d09c6e5a3e6862c5e26885ef455', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=ShippingInvoice.pdf.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=HAS_PACKED_CODE\tsev=Z7NG6\tsha256Hash=cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=ShippingInvoice.pdf.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=KNOWN_DOWNLOADER\tsev=Z7NG6\tsha256Hash=cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=ShippingInvoice.pdf.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=ENUMERATE_PROCESSES\tsev=Z7NG6\tsha256Hash=cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=ShippingInvoice.pdf.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=SET_SYSTEM_SECURITY\tsev=Z7NG6\tsha256Hash=cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=ShippingInvoice.pdf.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=MODIFY_MEMORY_PROTECTION\tsev=Z7NG6\tsha256Hash=cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=ShippingInvoice.pdf.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=KNOWN_PASSWORD_STEALER\tsev=Z7NG6\tsha256Hash=cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=explorer.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=RUN_MALWARE_APP\tsev=Z7NG6\tsha256Hash=1e675cb7df214172f7eb0497f7275556038a0d09c6e5a3e6862c5e26885ef455', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=ShippingInvoice.pdf.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=MODIFY_PROCESS\tsev=Z7NG6\tsha256Hash=cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=ShippingInvoice.pdf.exe\tcat=INDICATOR\tincidentId=Z7NG6\tindicatorName=MALWARE_APP\tsev=Z7NG6\tsha256Hash=cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc', 'LEEF:2.0|CarbonBlack|Cloud|1.0|THREAT|x09|cat=THREAT\tdevTime=Apr-15-2016 06:54:00 GMT\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\tdeviceId=2004118\tdeviceType=WINDOWS\teventId=f279d0e6035211e6be8701df2c083974\tidentHostName=\tidentSrc=\tincidentId=Z7NG6\trealm=default\tresource=COMPANY\\Demo_CaretoPC\truleName=syslog alert\tsev=7\tsummary=A known virus (Sality: Keylogger, Password or Data stealer, Backdoor) was detected running.\ttargetPriorityType=MEDIUM\turl=https://testserver.company.net/ui#investigate/events/device/2004118/incident/Z7NG6', 'LEEF:2.0|CarbonBlack|Cloud|1.0|POLICY_ACTION|x09|action=TERMINATE\tapplicationName=firefox.exe\tcat=POLICY_ACTION\tdevTime=Feb-05-2015 19:07:43 GMT\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\tdeviceId=100\tdeviceType=WINDOWS\teventId=EV1\tidentHostName=\tidentSrc=55.33.22.11\trealm=Executives\treputation=KNOWN_MALWARE\tresource=testers-pc\truleName=Alert Rule 1\tsev=1\tsha256=2552332222112552332222112552332222112552332222112552332222112552\tsummary=\ttargetPriorityType=HIGH\turl=http://carbonblack.com/ui#device/100/hash/2552332222112552332222112552332222112552332222112552332222112552/app/firefox.exe/keyword/terminate policy action', 'LEEF:2.0|CarbonBlack|Cloud|1.0|INDICATOR|x09|applicationName=powershell.exe\tcat=INDICATOR\tincidentId=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660\tindicatorName=565660-0\tsev=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660\tsha256Hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436', 'LEEF:2.0|CarbonBlack|Cloud|1.0|THREAT_HUNTER|x09|cat=THREAT_HUNTER\tdevTime=Apr-07-2019 15:43:31 GMT\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\tdeviceId=18900\tdeviceType=WINDOWS\teventId=None\tidentHostName=\tidentSrc=192.168.81.148\tincidentId=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660\tprocessGuid=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf\tprocessPath=c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe\trealm=sm-detection\treportName=PowerShell - File and Directory Discovery Enumeration\treputation=TRUSTED_WHITE_LIST\tresource=win-559j1nqvfgj\truleName=sm-sentinel-notification\trunState=RAN\tsev=1\tsha256=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436\tsummary=PowerShell - File and Directory Discovery Enumeration\ttargetPriorityType=MEDIUM\turl=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660\twatchlists=ATT&CK Framework']

json_notifications = [{'threatInfo': {'incidentId': 'Z7NG6', 'score': 7, 'summary': 'A known virus (Sality: Keylogger, Password or Data stealer, Backdoor) was detected running.', 'indicators': [{'indicatorName': 'PACKED_CALL', 'applicationName': 'ShippingInvoice.pdf.exe', 'sha256Hash': 'cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc'}, {'indicatorName': 'TARGET_MALWARE_APP', 'applicationName': 'explorer.exe', 'sha256Hash': '1e675cb7df214172f7eb0497f7275556038a0d09c6e5a3e6862c5e26885ef455'}, {'indicatorName': 'HAS_PACKED_CODE', 'applicationName': 'ShippingInvoice.pdf.exe', 'sha256Hash': 'cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc'}, {'indicatorName': 'KNOWN_DOWNLOADER', 'applicationName': 'ShippingInvoice.pdf.exe', 'sha256Hash': 'cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc'}, {'indicatorName': 'ENUMERATE_PROCESSES', 'applicationName': 'ShippingInvoice.pdf.exe', 'sha256Hash': 'cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc'}, {'indicatorName': 'SET_SYSTEM_SECURITY', 'applicationName': 'ShippingInvoice.pdf.exe', 'sha256Hash': 'cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc'}, {'indicatorName': 'MODIFY_MEMORY_PROTECTION', 'applicationName': 'ShippingInvoice.pdf.exe', 'sha256Hash': 'cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc'}, {'indicatorName': 'KNOWN_PASSWORD_STEALER', 'applicationName': 'ShippingInvoice.pdf.exe', 'sha256Hash': 'cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc'}, {'indicatorName': 'RUN_MALWARE_APP', 'applicationName': 'explorer.exe', 'sha256Hash': '1e675cb7df214172f7eb0497f7275556038a0d09c6e5a3e6862c5e26885ef455'}, {'indicatorName': 'MODIFY_PROCESS', 'applicationName': 'ShippingInvoice.pdf.exe', 'sha256Hash': 'cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc'}, {'indicatorName': 'MALWARE_APP', 'applicationName': 'ShippingInvoice.pdf.exe', 'sha256Hash': 'cfe0ae57f314a9f747a7cec605907cdaf1984b3cdea74ee8d5893d00ae0886cc'}], 'time': 1460703240678}, 'url': 'https://testserver.company.net/ui#investigate/events/device/2004118/incident/Z7NG6', 'eventTime': 1460703240678, 'eventId': 'f279d0e6035211e6be8701df2c083974', 'eventDescription': '[syslog alert] [Cb Defense has detected a threat against your company.] [https://testserver.company.net/ui#device/2004118/incident/Z7NG6] [A known virus (Sality: Keylogger, Password or Data stealer, Backdoor) was detected running.] [Incident id: Z7NG6] [Threat score: 7] [Group: default] [Email: FirstName.LastName@company.net.demo] [Name: Demo_CaretoPC] [Type and OS: WINDOWS XP x86 SP: 0]\n', 'deviceInfo': {'email': 'COMPANY\\FirstName.LastName', 'groupName': 'default', 'internalIpAddress': '', 'externalIpAddress': '', 'deviceType': 'WINDOWS', 'deviceVersion': 'XP x86 SP: 0', 'targetPriorityType': 'MEDIUM', 'deviceId': 2004118, 'deviceName': 'COMPANY\\Demo_CaretoPC', 'deviceHostName': '', 'targetPriorityCode': 0}, 'ruleName': 'syslog alert', 'type': 'THREAT', 'source': 'test'}, {'policyAction': {'sha256Hash': '2552332222112552332222112552332222112552332222112552332222112552', 'action': 'TERMINATE', 'reputation': 'KNOWN_MALWARE', 'applicationName': 'firefox.exe'}, 'type': 'POLICY_ACTION', 'eventTime': 1423163263482, 'eventId': 'EV1', 'url': 'http://carbonblack.com/ui#device/100/hash/2552332222112552332222112552332222112552332222112552332222112552/app/firefox.exe/keyword/terminate policy action', 'deviceInfo': {'deviceType': 'WINDOWS', 'email': 'tester@carbonblack.com', 'deviceId': 100, 'deviceName': 'testers-pc', 'deviceHostName': '', 'deviceVersion': '7 SP1', 'targetPriorityType': 'HIGH', 'targetPriorityCode': 0, 'internalIpAddress': '55.33.22.11', 'groupName': 'Executives', 'externalIpAddress': '255.233.222.211'}, 'eventDescription': 'Policy action 1', 'ruleName': 'Alert Rule 1', 'source': 'test'}, {'threatHunterInfo': {'incidentId': 'WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660', 'score': 1, 'summary': 'PowerShell - File and Directory Discovery Enumeration', 'time': 1554652050250, 'indicators': [{'applicationName': 'powershell.exe', 'sha256Hash': 'ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436', 'indicatorName': '565660-0'}], 'watchLists': [{'id': 'a3xW2ZiaRyAqRtuVES8Q', 'name': 'ATT&CK Framework', 'alert': 'true'}], 'iocId': '565660-0', 'count': 0, 'dismissed': 'false', 'documentGuid': '7a9fQEsTRfuFmXcogI8CMQ', 'firstActivityTime': 1554651811577, 'md5': '097ce5761c89434367598b34fe32893b', 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf', 'processPath': 'c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe', 'reportName': 'PowerShell - File and Directory Discovery Enumeration', 'reportId': 'j0MkcneCQXy1fIbhber6rw-565660', 'reputation': 'TRUSTED_WHITE_LIST', 'responseAlarmId': 'WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660', 'responseSeverity': 1, 'runState': 'RAN', 'sha256': 'ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436', 'status': 'UNRESOLVED', 'tags': '', 'targetPriority': 'MEDIUM', 'threatCause': {'reputation': 'TRUSTED_WHITE_LIST', 'actor': 'ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436', 'actorName': 'powershell.exe', 'reason': 'Process powershell.exe was detected by the report "PowerShell - File and Directory Discovery Enumeration" in watchlist "ATT&CK Framework"', 'actorType': '', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorProcessPPid': '', 'causeEventId': '', 'originSourceType': 'UNKNOWN'}, 'threatId': 'a2b724aa094af97c06c758d325240460', 'lastUpdatedTime': 0, 'orgId': 428}, 'eventDescription': '[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660] [PowerShell - File and Directory Discovery Enumeration] [Incident id: WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660] [Threat score: 1] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 1]\n', 'eventTime': 1554651811577, 'deviceInfo': {'deviceId': 18900, 'targetPriorityCode': 0, 'groupName': 'sm-detection', 'deviceName': 'win-559j1nqvfgj', 'deviceType': 'WINDOWS', 'email': 'smultani@carbonblack.com', 'deviceHostName': '', 'deviceVersion': 'pscr-sensor', 'targetPriorityType': 'MEDIUM', 'uemId': '', 'internalIpAddress': '192.168.81.148', 'externalIpAddress': '73.69.152.214'}, 'url': 'https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660', 'ruleName': 'sm-sentinel-notification', 'type': 'THREAT_HUNTER', 'source': 'test'}]
