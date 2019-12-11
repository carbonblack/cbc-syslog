# -*- coding: utf-8 -*-


null = ""
true = "true"
false = "false"


test_data_threat_hunter={
    "notifications": [
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
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660",
                "score": 1,
                "summary": "PowerShell - File and Directory Discovery Enumeration",
                "time": 1554652050260,
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
            "eventDescription": "[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf&deviceId=18900] [PowerShell - File and Directory Discovery Enumeration] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: 565660-0] [Severity: 1]",
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
            "url": "https://defense-eap01.conferdeploy.net",
            "ruleName": "sm-sentinel-watchlist",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "score": 10,
                "summary": "T1003 - Credential Dumping #2",
                "time": 1554652058988,
                "indicators": [
                    {
                        "applicationName": "mimikatz.exe",
                        "sha256Hash": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                        "indicatorName": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "3ExgIixySwmbRuaXoxxKeA",
                        "name": "Carbon Black Advanced Threats",
                        "alert": true
                    }
                ],
                "iocId": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "NoKzSz7wTzSil0ur7wYG0Q",
                "firstActivityTime": 1554651774855,
                "md5": "9e9ea5e8a16995124ba6e75bad4c6abe",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0",
                "processPath": "c:\\users\\smultani\\music\\mimikatz_trunk (1)\\win32\\mimikatz.exe",
                "reportName": "T1003 - Credential Dumping #2",
                "reportId": "1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "reputation": "KNOWN_MALWARE",
                "responseAlarmId": "WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "responseSeverity": 10,
                "runState": "RAN",
                "sha256": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "KNOWN_MALWARE",
                    "actor": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                    "actorName": "mimikatz.exe",
                    "reason": "Process mimikatz.exe was detected by the report \"T1003 - Credential Dumping #2\" in watchlist \"Carbon Black Advanced Threats\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "5f1763e2ea26c424e8a84ec6b1090983",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [T1003 - Credential Dumping #2] [Incident id: WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [Threat score: 10] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 10]\n",
            "eventTime": 1554651774855,
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
            "url": "https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
            "ruleName": "sm-sentinel-notification",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "score": 10,
                "summary": "T1003 - Credential Dumping #2",
                "time": 1554652058999,
                "indicators": [
                    {
                        "applicationName": "mimikatz.exe",
                        "sha256Hash": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                        "indicatorName": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "3ExgIixySwmbRuaXoxxKeA",
                        "name": "Carbon Black Advanced Threats",
                        "alert": true
                    }
                ],
                "iocId": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "NoKzSz7wTzSil0ur7wYG0Q",
                "firstActivityTime": 1554651774855,
                "md5": "9e9ea5e8a16995124ba6e75bad4c6abe",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0",
                "processPath": "c:\\users\\smultani\\music\\mimikatz_trunk (1)\\win32\\mimikatz.exe",
                "reportName": "T1003 - Credential Dumping #2",
                "reportId": "1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "reputation": "KNOWN_MALWARE",
                "responseAlarmId": "WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "responseSeverity": 10,
                "runState": "RAN",
                "sha256": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "KNOWN_MALWARE",
                    "actor": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                    "actorName": "mimikatz.exe",
                    "reason": "Process mimikatz.exe was detected by the report \"T1003 - Credential Dumping #2\" in watchlist \"Carbon Black Advanced Threats\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "5f1763e2ea26c424e8a84ec6b1090983",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0&deviceId=18900] [T1003 - Credential Dumping #2] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: b7e9fd8e-febe-478c-8f44-2e90e0d10507-0] [Severity: 10]",
            "eventTime": 1554651774855,
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
            "url": "https://defense-eap01.conferdeploy.net",
            "ruleName": "sm-sentinel-watchlist",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "score": 10,
                "summary": "T1003 - Credential Dumping #2",
                "time": 1554652062174,
                "indicators": [
                    {
                        "applicationName": "mimikatz.exe",
                        "sha256Hash": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                        "indicatorName": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "3ExgIixySwmbRuaXoxxKeA",
                        "name": "Carbon Black Advanced Threats",
                        "alert": true
                    }
                ],
                "iocId": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "F-OinTckReGkfHVvNZqe1w",
                "firstActivityTime": 1554651550298,
                "md5": "9e9ea5e8a16995124ba6e75bad4c6abe",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8",
                "processPath": "c:\\users\\smultani\\desktop\\mimikatz_trunk (1)\\win32\\mimikatz.exe",
                "reportName": "T1003 - Credential Dumping #2",
                "reportId": "1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "reputation": "KNOWN_MALWARE",
                "responseAlarmId": "WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "responseSeverity": 10,
                "runState": "RAN",
                "sha256": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "KNOWN_MALWARE",
                    "actor": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                    "actorName": "mimikatz.exe",
                    "reason": "Process mimikatz.exe was detected by the report \"T1003 - Credential Dumping #2\" in watchlist \"Carbon Black Advanced Threats\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "5f1763e2ea26c424e8a84ec6b1090983",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8&deviceId=18900] [T1003 - Credential Dumping #2] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: b7e9fd8e-febe-478c-8f44-2e90e0d10507-0] [Severity: 10]",
            "eventTime": 1554651550298,
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
            "url": "https://defense-eap01.conferdeploy.net",
            "ruleName": "sm-sentinel-watchlist",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "score": 10,
                "summary": "T1003 - Credential Dumping #2",
                "time": 1554652062191,
                "indicators": [
                    {
                        "applicationName": "mimikatz.exe",
                        "sha256Hash": "38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac",
                        "indicatorName": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "3ExgIixySwmbRuaXoxxKeA",
                        "name": "Carbon Black Advanced Threats",
                        "alert": true
                    }
                ],
                "iocId": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "qgp18td2TFK2Dw3YB2MuSA",
                "firstActivityTime": 1554651734686,
                "md5": "a3298b7614ff07f91301655edd58e9d7",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9",
                "processPath":"c:\\users\\smultani\\music\\mimikatz_trunk (1)\d\\mimikatz.exe",
                "reportName": "T1003 - Credential Dumping #2",
                "reportId": "1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "reputation": "PUP",
                "responseAlarmId": "WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "responseSeverity": 10,
                "runState": "RAN",
                "sha256": "38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "PUP",
                    "actor": "38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac",
                    "actorName": "mimikatz.exe",
                    "reason": "Process mimikatz.exe was detected by the report \"T1003 - Credential Dumping #2\" in watchlist \"Carbon Black Advanced Threats\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "5f1763e2ea26c424e8a84ec6b1090983",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [T1003 - Credential Dumping #2] [Incident id: WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [Threat score: 10] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 10]\n",
            "eventTime": 1554651734686,
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
            "url": "https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
            "ruleName": "sm-sentinel-notification",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "score": 10,
                "summary": "T1003 - Credential Dumping #2",
                "time": 1554652062248,
                "indicators": [
                    {
                        "applicationName": "mimikatz.exe",
                        "sha256Hash": "38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac",
                        "indicatorName": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "3ExgIixySwmbRuaXoxxKeA",
                        "name": "Carbon Black Advanced Threats",
                        "alert": true
                    }
                ],
                "iocId": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "qgp18td2TFK2Dw3YB2MuSA",
                "firstActivityTime": 1554651734686,
                "md5": "a3298b7614ff07f91301655edd58e9d7",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9",
                "processPath":"c:\\users\\smultani\\music\\mimikatz_trunk (1)\d\\mimikatz.exe",
                "reportName": "T1003 - Credential Dumping #2",
                "reportId": "1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "reputation": "PUP",
                "responseAlarmId": "WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "responseSeverity": 10,
                "runState": "RAN",
                "sha256": "38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "PUP",
                    "actor": "38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac",
                    "actorName": "mimikatz.exe",
                    "reason": "Process mimikatz.exe was detected by the report \"T1003 - Credential Dumping #2\" in watchlist \"Carbon Black Advanced Threats\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "5f1763e2ea26c424e8a84ec6b1090983",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9&deviceId=18900] [T1003 - Credential Dumping #2] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: b7e9fd8e-febe-478c-8f44-2e90e0d10507-0] [Severity: 10]",
            "eventTime": 1554651734686,
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
            "url": "https://defense-eap01.conferdeploy.net",
            "ruleName": "sm-sentinel-watchlist",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "score": 10,
                "summary": "T1003 - Credential Dumping #2",
                "time": 1554652062265,
                "indicators": [
                    {
                        "applicationName": "mimikatz.exe",
                        "sha256Hash": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                        "indicatorName": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "3ExgIixySwmbRuaXoxxKeA",
                        "name": "Carbon Black Advanced Threats",
                        "alert": true
                    }
                ],
                "iocId": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "F-OinTckReGkfHVvNZqe1w",
                "firstActivityTime": 1554651550298,
                "md5": "9e9ea5e8a16995124ba6e75bad4c6abe",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8",
                "processPath": "c:\\users\\smultani\\desktop\\mimikatz_trunk (1)\\win32\\mimikatz.exe",
                "reportName": "T1003 - Credential Dumping #2",
                "reportId": "1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "reputation": "KNOWN_MALWARE",
                "responseAlarmId": "WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "responseSeverity": 10,
                "runState": "RAN",
                "sha256": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "KNOWN_MALWARE",
                    "actor": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                    "actorName": "mimikatz.exe",
                    "reason": "Process mimikatz.exe was detected by the report \"T1003 - Credential Dumping #2\" in watchlist \"Carbon Black Advanced Threats\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "5f1763e2ea26c424e8a84ec6b1090983",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [T1003 - Credential Dumping #2] [Incident id: WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [Threat score: 10] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 10]\n",
            "eventTime": 1554651550298,
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
            "url": "https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
            "ruleName": "sm-sentinel-notification",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5",
                "score": 9,
                "summary": "Memory Grab using ProcDump",
                "time": 1554652418230,
                "indicators": [
                    {
                        "applicationName": "procdump64.exe",
                        "sha256Hash": "16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5",
                        "indicatorName": "47a50561-e6ff-4106-8df1-5777f70a98d5-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "JBeEYzBcQpSMXu3lWoSv8w",
                        "name": "Carbon Black Community",
                        "alert": true
                    }
                ],
                "iocId": "47a50561-e6ff-4106-8df1-5777f70a98d5-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "L8UMm1dOR76_T6nBv-PBFw",
                "firstActivityTime": 1554651976107,
                "md5": "a92669ec8852230a10256ac23bbf4489",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9",
                "processPath": "c:\\users\\smultani\\downloads\\procdump\\procdump64.exe",
                "reportName": "Memory Grab using ProcDump",
                "reportId": "n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5",
                "reputation": "TRUSTED_WHITE_LIST",
                "responseAlarmId": "WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5",
                "responseSeverity": 9,
                "runState": "RAN",
                "sha256": "16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "TRUSTED_WHITE_LIST",
                    "actor": "16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5",
                    "actorName": "procdump64.exe",
                    "reason": "Process procdump64.exe was detected by the report \"Memory Grab using ProcDump\" in watchlist \"Carbon Black Community\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "db260acf65984a2c74ae0c41a8e08086",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5] [Memory Grab using ProcDump] [Incident id: WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5] [Threat score: 9] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 9]\n",
            "eventTime": 1554651976107,
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
            "url": "https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5",
            "ruleName": "sm-sentinel-notification",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06",
                "score": 9,
                "summary": "T1003 - Credential Dumping #3",
                "time": 1554652418279,
                "indicators": [
                    {
                        "applicationName": "procdump.exe",
                        "sha256Hash": "05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad",
                        "indicatorName": "7aa6e57a-6fa8-423d-b997-427565bf7a06-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "3ExgIixySwmbRuaXoxxKeA",
                        "name": "Carbon Black Advanced Threats",
                        "alert": true
                    }
                ],
                "iocId": "7aa6e57a-6fa8-423d-b997-427565bf7a06-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "NM1Pn_drQ3airxKooRokmQ",
                "firstActivityTime": 1554651828170,
                "md5": "6a09bc6c19c4236c0bd8a01953371a29",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9",
                "processPath": "c:\\users\\smultani\\downloads\\procdump\\procdump.exe",
                "reportName": "T1003 - Credential Dumping #3",
                "reportId": "1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06",
                "reputation": "TRUSTED_WHITE_LIST",
                "responseAlarmId": "WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06",
                "responseSeverity": 9,
                "runState": "RAN",
                "sha256": "05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "TRUSTED_WHITE_LIST",
                    "actor": "05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad",
                    "actorName": "procdump.exe",
                    "reason": "Process procdump.exe was detected by the report \"T1003 - Credential Dumping #3\" in watchlist \"Carbon Black Advanced Threats\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "ddb41379ce092f02c635851f4a9364f2",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06] [T1003 - Credential Dumping #3] [Incident id: WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06] [Threat score: 9] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 9]\n",
            "eventTime": 1554651828170,
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
            "url": "https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06",
            "ruleName": "sm-sentinel-notification",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "score": 10,
                "summary": "T1003 - Credential Dumping #2",
                "time": 1554652418305,
                "indicators": [
                    {
                        "applicationName": "mimikatz.exe",
                        "sha256Hash": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                        "indicatorName": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "3ExgIixySwmbRuaXoxxKeA",
                        "name": "Carbon Black Advanced Threats",
                        "alert": true
                    }
                ],
                "iocId": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "FtA0ybjVRJuJ2VohA5E-Lw",
                "firstActivityTime": 1554651837865,
                "md5": "9e9ea5e8a16995124ba6e75bad4c6abe",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502",
                "processPath": "c:\\users\\smultani\\music\\mimikatz_trunk (1)\\win32\\mimikatz.exe",
                "reportName": "T1003 - Credential Dumping #2",
                "reportId": "1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "reputation": "KNOWN_MALWARE",
                "responseAlarmId": "WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "responseSeverity": 10,
                "runState": "RAN",
                "sha256": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "KNOWN_MALWARE",
                    "actor": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                    "actorName": "mimikatz.exe",
                    "reason": "Process mimikatz.exe was detected by the report \"T1003 - Credential Dumping #2\" in watchlist \"Carbon Black Advanced Threats\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "5f1763e2ea26c424e8a84ec6b1090983",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [T1003 - Credential Dumping #2] [Incident id: WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [Threat score: 10] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 10]\n",
            "eventTime": 1554651837865,
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
            "url": "https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
            "ruleName": "sm-sentinel-notification",
            "type": "THREAT_HUNTER"
        },
        {
            "threatHunterInfo": {
                "incidentId": "WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "score": 10,
                "summary": "T1003 - Credential Dumping #2",
                "time": 1554652418330,
                "indicators": [
                    {
                        "applicationName": "mimikatz.exe",
                        "sha256Hash": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                        "indicatorName": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0"
                    }
                ],
                "watchLists": [
                    {
                        "id": "3ExgIixySwmbRuaXoxxKeA",
                        "name": "Carbon Black Advanced Threats",
                        "alert": true
                    }
                ],
                "iocId": "b7e9fd8e-febe-478c-8f44-2e90e0d10507-0",
                "count": 0,
                "dismissed": false,
                "documentGuid": "FtA0ybjVRJuJ2VohA5E-Lw",
                "firstActivityTime": 1554651837865,
                "md5": "9e9ea5e8a16995124ba6e75bad4c6abe",
                "policyId": 9815,
                "processGuid": "WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502",
                "processPath": "c:\\users\\smultani\\music\\mimikatz_trunk (1)\\win32\\mimikatz.exe",
                "reportName": "T1003 - Credential Dumping #2",
                "reportId": "1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "reputation": "KNOWN_MALWARE",
                "responseAlarmId": "WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507",
                "responseSeverity": 10,
                "runState": "RAN",
                "sha256": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                "status": "UNRESOLVED",
                "tags": null,
                "targetPriority": "MEDIUM",
                "threatCause": {
                    "reputation": "KNOWN_MALWARE",
                    "actor": "6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be",
                    "actorName": "mimikatz.exe",
                    "reason": "Process mimikatz.exe was detected by the report \"T1003 - Credential Dumping #2\" in watchlist \"Carbon Black Advanced Threats\"",
                    "actorType": null,
                    "threatCategory": "RESPONSE_WATCHLIST",
                    "actorProcessPPid": null,
                    "causeEventId": null,
                    "originSourceType": "UNKNOWN"
                },
                "threatId": "5f1763e2ea26c424e8a84ec6b1090983",
                "lastUpdatedTime": 0,
                "orgId": 428
            },
            "eventDescription": "[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502&deviceId=18900] [T1003 - Credential Dumping #2] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: b7e9fd8e-febe-478c-8f44-2e90e0d10507-0] [Severity: 10]",
            "eventTime": 1554651837865,
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
            "url": "https://defense-eap01.conferdeploy.net",
            "ruleName": "sm-sentinel-watchlist",
            "type": "THREAT_HUNTER"
        }
   ],
    "success": true,
    "message": "Success"
}

cef_output_notification_th="""test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|PowerShell - File and Directory Discovery Enumeration|1|rt="Apr 07 2019 15:43:31" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660" hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|PowerShell - File and Directory Discovery Enumeration|1|rt="Apr 07 2019 15:43:31" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660" hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|T1003 - Credential Dumping #2|10|rt="Apr 07 2019 15:42:54" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|T1003 - Credential Dumping #2|10|rt="Apr 07 2019 15:42:54" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|T1003 - Credential Dumping #2|10|rt="Apr 07 2019 15:39:10" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|T1003 - Credential Dumping #2|10|rt="Apr 07 2019 15:42:14" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" hash=38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|T1003 - Credential Dumping #2|10|rt="Apr 07 2019 15:42:14" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" hash=38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|T1003 - Credential Dumping #2|10|rt="Apr 07 2019 15:39:10" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|Memory Grab using ProcDump|9|rt="Apr 07 2019 15:46:16" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5" hash=16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|T1003 - Credential Dumping #3|9|rt="Apr 07 2019 15:43:48" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06" hash=05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|T1003 - Credential Dumping #2|10|rt="Apr 07 2019 15:43:57" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Threat_Hunter|T1003 - Credential Dumping #2|10|rt="Apr 07 2019 15:43:57" dvchost=win-559j1nqvfgj duser=smultani@carbonblack.com dvc=192.168.81.148 cs3Label="Link" cs3="https://defense-eap01.conferdeploy.net" cs4Label="Threat_ID" cs4="WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507" hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be"""

leef_output_notification_th="""LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=1	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=PowerShell - File and Directory Discovery Enumeration	groupName=sm-detection	reputation=TRUSTED_WHITE_LIST	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:31 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|565660-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=1	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=PowerShell - File and Directory Discovery Enumeration	groupName=sm-detection	reputation=TRUSTED_WHITE_LIST	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:31 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=powershell.exe	indicatorName=565660-0	sha256Hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=1	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=PowerShell - File and Directory Discovery Enumeration	groupName=sm-detection	reputation=TRUSTED_WHITE_LIST	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:31 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|565660-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=1	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=PowerShell - File and Directory Discovery Enumeration	groupName=sm-detection	reputation=TRUSTED_WHITE_LIST	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:31 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=powershell.exe	indicatorName=565660-0	sha256Hash=ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:42:54 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|b7e9fd8e-febe-478c-8f44-2e90e0d10507-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:42:54 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=mimikatz.exe	indicatorName=b7e9fd8e-febe-478c-8f44-2e90e0d10507-0	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:42:54 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|b7e9fd8e-febe-478c-8f44-2e90e0d10507-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:42:54 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=mimikatz.exe	indicatorName=b7e9fd8e-febe-478c-8f44-2e90e0d10507-0	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:39:10 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|b7e9fd8e-febe-478c-8f44-2e90e0d10507-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:39:10 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=mimikatz.exe	indicatorName=b7e9fd8e-febe-478c-8f44-2e90e0d10507-0	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=PUP	deviceType=WINDOWS	devTime=Apr-07-2019 15:42:14 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|b7e9fd8e-febe-478c-8f44-2e90e0d10507-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=PUP	deviceType=WINDOWS	devTime=Apr-07-2019 15:42:14 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=mimikatz.exe	indicatorName=b7e9fd8e-febe-478c-8f44-2e90e0d10507-0	sha256Hash=38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=PUP	deviceType=WINDOWS	devTime=Apr-07-2019 15:42:14 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|b7e9fd8e-febe-478c-8f44-2e90e0d10507-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=PUP	deviceType=WINDOWS	devTime=Apr-07-2019 15:42:14 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=mimikatz.exe	indicatorName=b7e9fd8e-febe-478c-8f44-2e90e0d10507-0	sha256Hash=38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:39:10 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|b7e9fd8e-febe-478c-8f44-2e90e0d10507-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:39:10 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=mimikatz.exe	indicatorName=b7e9fd8e-febe-478c-8f44-2e90e0d10507-0	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=9	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=Memory Grab using ProcDump	groupName=sm-detection	reputation=TRUSTED_WHITE_LIST	deviceType=WINDOWS	devTime=Apr-07-2019 15:46:16 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|47a50561-e6ff-4106-8df1-5777f70a98d5-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=9	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=Memory Grab using ProcDump	groupName=sm-detection	reputation=TRUSTED_WHITE_LIST	deviceType=WINDOWS	devTime=Apr-07-2019 15:46:16 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=procdump64.exe	indicatorName=47a50561-e6ff-4106-8df1-5777f70a98d5-0	sha256Hash=16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=9	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #3	groupName=sm-detection	reputation=TRUSTED_WHITE_LIST	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:48 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|7aa6e57a-6fa8-423d-b997-427565bf7a06-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=9	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #3	groupName=sm-detection	reputation=TRUSTED_WHITE_LIST	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:48 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=procdump.exe	indicatorName=7aa6e57a-6fa8-423d-b997-427565bf7a06-0	sha256Hash=05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:57 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|b7e9fd8e-febe-478c-8f44-2e90e0d10507-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-notification	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:57 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=mimikatz.exe	indicatorName=b7e9fd8e-febe-478c-8f44-2e90e0d10507-0	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
LEEF:2.0|CarbonBlack|CbDefense|0.1|THREAT|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:57 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor
LEEF:2.0|CarbonBlack|CbDefense|0.1|b7e9fd8e-febe-478c-8f44-2e90e0d10507-0|x09|identHostName=win-559j1nqvfgj	deviceName=win-559j1nqvfgj	sev=10	deviceHostName=	cat=THREAT_HUNTER	externalIpAddress=73.69.152.214	deviceId=18900	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be	ruleName=sm-sentinel-watchlist	identSrc=192.168.81.148	src=192.168.81.148	eventId=None	uemId=	resource=win-559j1nqvfgj	targetPriorityCode=0	url=https://defense-eap01.conferdeploy.net	internalIpAddress=192.168.81.148	dst=192.168.81.148	summary=T1003 - Credential Dumping #2	groupName=sm-detection	reputation=KNOWN_MALWARE	deviceType=WINDOWS	devTime=Apr-07-2019 15:43:57 GMT	targetPriorityType=MEDIUM	signature=Threat_Hunter	devTimeFormat=MMM dd yyyy HH:mm:ss z	incidentId=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507	type=THREAT	email=smultani@carbonblack.com	deviceVersion=pscr-sensor	applicationName=mimikatz.exe	indicatorName=b7e9fd8e-febe-478c-8f44-2e90e0d10507-0	sha256Hash=6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be
"""

json_output_notification_th=[{'eventTime': 1554651811577, 'eventDescription': '[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660] [PowerShell - File and Directory Discovery Enumeration] [Incident id: WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660] [Threat score: 1] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 1]\n', 'url': 'https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-notification', 'threatHunterInfo': {'responseSeverity': 1, 'reportName': 'PowerShell - File and Directory Discovery Enumeration', 'documentGuid': '7a9fQEsTRfuFmXcogI8CMQ', 'runState': 'RAN', 'firstActivityTime': 1554651811577, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 1, 'indicators': [{'applicationName': 'powershell.exe', 'indicatorName': '565660-0', 'sha256Hash': 'ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436'}], 'sha256': 'ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436', 'status': 'UNRESOLVED', 'processPath': 'c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': 'a3xW2ZiaRyAqRtuVES8Q', 'name': 'ATT&CK Framework'}], 'time': 1554652050250, 'reportId': 'j0MkcneCQXy1fIbhber6rw-565660', 'responseAlarmId': 'WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660', 'iocId': '565660-0', 'md5': '097ce5761c89434367598b34fe32893b', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process powershell.exe was detected by the report "PowerShell - File and Directory Discovery Enumeration" in watchlist "ATT&CK Framework"', 'reputation': 'TRUSTED_WHITE_LIST', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'powershell.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': 'ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436'}, 'lastUpdatedTime': 0, 'threatId': 'a2b724aa094af97c06c758d325240460', 'summary': 'PowerShell - File and Directory Discovery Enumeration', 'reputation': 'TRUSTED_WHITE_LIST', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf', 'incidentId': 'WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651811577, 'eventDescription': '[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf&deviceId=18900] [PowerShell - File and Directory Discovery Enumeration] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: 565660-0] [Severity: 1]', 'url': 'https://defense-eap01.conferdeploy.net', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-watchlist', 'threatHunterInfo': {'responseSeverity': 1, 'reportName': 'PowerShell - File and Directory Discovery Enumeration', 'documentGuid': '7a9fQEsTRfuFmXcogI8CMQ', 'runState': 'RAN', 'firstActivityTime': 1554651811577, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 1, 'indicators': [{'applicationName': 'powershell.exe', 'indicatorName': '565660-0', 'sha256Hash': 'ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436'}], 'sha256': 'ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436', 'status': 'UNRESOLVED', 'processPath': 'c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': 'a3xW2ZiaRyAqRtuVES8Q', 'name': 'ATT&CK Framework'}], 'time': 1554652050260, 'reportId': 'j0MkcneCQXy1fIbhber6rw-565660', 'responseAlarmId': 'WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660', 'iocId': '565660-0', 'md5': '097ce5761c89434367598b34fe32893b', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process powershell.exe was detected by the report "PowerShell - File and Directory Discovery Enumeration" in watchlist "ATT&CK Framework"', 'reputation': 'TRUSTED_WHITE_LIST', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'powershell.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': 'ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436'}, 'lastUpdatedTime': 0, 'threatId': 'a2b724aa094af97c06c758d325240460', 'summary': 'PowerShell - File and Directory Discovery Enumeration', 'reputation': 'TRUSTED_WHITE_LIST', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf', 'incidentId': 'WNEXFKQ7-000049d4-00001ef0-00000000-1d4ed58a5f07dbf-j0MkcneCQXy1fIbhber6rw-565660'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651774855, 'eventDescription': '[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [T1003 - Credential Dumping #2] [Incident id: WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [Threat score: 10] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 10]\n', 'url': 'https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-notification', 'threatHunterInfo': {'responseSeverity': 10, 'reportName': 'T1003 - Credential Dumping #2', 'documentGuid': 'NoKzSz7wTzSil0ur7wYG0Q', 'runState': 'RAN', 'firstActivityTime': 1554651774855, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 10, 'indicators': [{'applicationName': 'mimikatz.exe', 'indicatorName': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'sha256Hash': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}], 'sha256': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\music\\mimikatz_trunk (1)\\win32\\mimikatz.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': '3ExgIixySwmbRuaXoxxKeA', 'name': 'Carbon Black Advanced Threats'}], 'time': 1554652058988, 'reportId': '1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'responseAlarmId': 'WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'iocId': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'md5': '9e9ea5e8a16995124ba6e75bad4c6abe', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process mimikatz.exe was detected by the report "T1003 - Credential Dumping #2" in watchlist "Carbon Black Advanced Threats"', 'reputation': 'KNOWN_MALWARE', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'mimikatz.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}, 'lastUpdatedTime': 0, 'threatId': '5f1763e2ea26c424e8a84ec6b1090983', 'summary': 'T1003 - Credential Dumping #2', 'reputation': 'KNOWN_MALWARE', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0', 'incidentId': 'WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651774855, 'eventDescription': '[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0&deviceId=18900] [T1003 - Credential Dumping #2] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: b7e9fd8e-febe-478c-8f44-2e90e0d10507-0] [Severity: 10]', 'url': 'https://defense-eap01.conferdeploy.net', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-watchlist', 'threatHunterInfo': {'responseSeverity': 10, 'reportName': 'T1003 - Credential Dumping #2', 'documentGuid': 'NoKzSz7wTzSil0ur7wYG0Q', 'runState': 'RAN', 'firstActivityTime': 1554651774855, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 10, 'indicators': [{'applicationName': 'mimikatz.exe', 'indicatorName': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'sha256Hash': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}], 'sha256': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\music\\mimikatz_trunk (1)\\win32\\mimikatz.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': '3ExgIixySwmbRuaXoxxKeA', 'name': 'Carbon Black Advanced Threats'}], 'time': 1554652058999, 'reportId': '1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'responseAlarmId': 'WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'iocId': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'md5': '9e9ea5e8a16995124ba6e75bad4c6abe', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process mimikatz.exe was detected by the report "T1003 - Credential Dumping #2" in watchlist "Carbon Black Advanced Threats"', 'reputation': 'KNOWN_MALWARE', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'mimikatz.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}, 'lastUpdatedTime': 0, 'threatId': '5f1763e2ea26c424e8a84ec6b1090983', 'summary': 'T1003 - Credential Dumping #2', 'reputation': 'KNOWN_MALWARE', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0', 'incidentId': 'WNEXFKQ7-000049d4-000013d8-00000000-1d4ed587c0142d0-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651550298, 'eventDescription': '[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8&deviceId=18900] [T1003 - Credential Dumping #2] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: b7e9fd8e-febe-478c-8f44-2e90e0d10507-0] [Severity: 10]', 'url': 'https://defense-eap01.conferdeploy.net', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-watchlist', 'threatHunterInfo': {'responseSeverity': 10, 'reportName': 'T1003 - Credential Dumping #2', 'documentGuid': 'F-OinTckReGkfHVvNZqe1w', 'runState': 'RAN', 'firstActivityTime': 1554651550298, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 10, 'indicators': [{'applicationName': 'mimikatz.exe', 'indicatorName': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'sha256Hash': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}], 'sha256': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\desktop\\mimikatz_trunk (1)\\win32\\mimikatz.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': '3ExgIixySwmbRuaXoxxKeA', 'name': 'Carbon Black Advanced Threats'}], 'time': 1554652062174, 'reportId': '1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'responseAlarmId': 'WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'iocId': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'md5': '9e9ea5e8a16995124ba6e75bad4c6abe', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process mimikatz.exe was detected by the report "T1003 - Credential Dumping #2" in watchlist "Carbon Black Advanced Threats"', 'reputation': 'KNOWN_MALWARE', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'mimikatz.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}, 'lastUpdatedTime': 0, 'threatId': '5f1763e2ea26c424e8a84ec6b1090983', 'summary': 'T1003 - Credential Dumping #2', 'reputation': 'KNOWN_MALWARE', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8', 'incidentId': 'WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651734686, 'eventDescription': '[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [T1003 - Credential Dumping #2] [Incident id: WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [Threat score: 10] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 10]\n', 'url': 'https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-notification', 'threatHunterInfo': {'responseSeverity': 10, 'reportName': 'T1003 - Credential Dumping #2', 'documentGuid': 'qgp18td2TFK2Dw3YB2MuSA', 'runState': 'RAN', 'firstActivityTime': 1554651734686, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 10, 'indicators': [{'applicationName': 'mimikatz.exe', 'indicatorName': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'sha256Hash': '38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac'}], 'sha256': '38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\music\\mimikatz_trunk (1)\\d\\mimikatz.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': '3ExgIixySwmbRuaXoxxKeA', 'name': 'Carbon Black Advanced Threats'}], 'time': 1554652062191, 'reportId': '1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'responseAlarmId': 'WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'iocId': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'md5': 'a3298b7614ff07f91301655edd58e9d7', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process mimikatz.exe was detected by the report "T1003 - Credential Dumping #2" in watchlist "Carbon Black Advanced Threats"', 'reputation': 'PUP', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'mimikatz.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac'}, 'lastUpdatedTime': 0, 'threatId': '5f1763e2ea26c424e8a84ec6b1090983', 'summary': 'T1003 - Credential Dumping #2', 'reputation': 'PUP', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9', 'incidentId': 'WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651734686, 'eventDescription': '[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9&deviceId=18900] [T1003 - Credential Dumping #2] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: b7e9fd8e-febe-478c-8f44-2e90e0d10507-0] [Severity: 10]', 'url': 'https://defense-eap01.conferdeploy.net', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-watchlist', 'threatHunterInfo': {'responseSeverity': 10, 'reportName': 'T1003 - Credential Dumping #2', 'documentGuid': 'qgp18td2TFK2Dw3YB2MuSA', 'runState': 'RAN', 'firstActivityTime': 1554651734686, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 10, 'indicators': [{'applicationName': 'mimikatz.exe', 'indicatorName': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'sha256Hash': '38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac'}], 'sha256': '38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\music\\mimikatz_trunk (1)\\d\\mimikatz.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': '3ExgIixySwmbRuaXoxxKeA', 'name': 'Carbon Black Advanced Threats'}], 'time': 1554652062248, 'reportId': '1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'responseAlarmId': 'WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'iocId': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'md5': 'a3298b7614ff07f91301655edd58e9d7', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process mimikatz.exe was detected by the report "T1003 - Credential Dumping #2" in watchlist "Carbon Black Advanced Threats"', 'reputation': 'PUP', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'mimikatz.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '38ff9593dcd07b0252ed3f1ad34ce7b538c522fd2a4d6ffef00f73767e75edac'}, 'lastUpdatedTime': 0, 'threatId': '5f1763e2ea26c424e8a84ec6b1090983', 'summary': 'T1003 - Credential Dumping #2', 'reputation': 'PUP', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9', 'incidentId': 'WNEXFKQ7-000049d4-00001e18-00000000-1d4ed58784102f9-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651550298, 'eventDescription': '[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [T1003 - Credential Dumping #2] [Incident id: WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [Threat score: 10] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 10]\n', 'url': 'https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-notification', 'threatHunterInfo': {'responseSeverity': 10, 'reportName': 'T1003 - Credential Dumping #2', 'documentGuid': 'F-OinTckReGkfHVvNZqe1w', 'runState': 'RAN', 'firstActivityTime': 1554651550298, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 10, 'indicators': [{'applicationName': 'mimikatz.exe', 'indicatorName': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'sha256Hash': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}], 'sha256': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\desktop\\mimikatz_trunk (1)\\win32\\mimikatz.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': '3ExgIixySwmbRuaXoxxKeA', 'name': 'Carbon Black Advanced Threats'}], 'time': 1554652062265, 'reportId': '1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'responseAlarmId': 'WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'iocId': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'md5': '9e9ea5e8a16995124ba6e75bad4c6abe', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process mimikatz.exe was detected by the report "T1003 - Credential Dumping #2" in watchlist "Carbon Black Advanced Threats"', 'reputation': 'KNOWN_MALWARE', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'mimikatz.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}, 'lastUpdatedTime': 0, 'threatId': '5f1763e2ea26c424e8a84ec6b1090983', 'summary': 'T1003 - Credential Dumping #2', 'reputation': 'KNOWN_MALWARE', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8', 'incidentId': 'WNEXFKQ7-000049d4-00000954-00000000-1d4ed5809bf5af8-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651976107, 'eventDescription': '[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5] [Memory Grab using ProcDump] [Incident id: WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5] [Threat score: 9] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 9]\n', 'url': 'https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-notification', 'threatHunterInfo': {'responseSeverity': 9, 'reportName': 'Memory Grab using ProcDump', 'documentGuid': 'L8UMm1dOR76_T6nBv-PBFw', 'runState': 'RAN', 'firstActivityTime': 1554651976107, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 9, 'indicators': [{'applicationName': 'procdump64.exe', 'indicatorName': '47a50561-e6ff-4106-8df1-5777f70a98d5-0', 'sha256Hash': '16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5'}], 'sha256': '16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\downloads\\procdump\\procdump64.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': 'JBeEYzBcQpSMXu3lWoSv8w', 'name': 'Carbon Black Community'}], 'time': 1554652418230, 'reportId': 'n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5', 'responseAlarmId': 'WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5', 'iocId': '47a50561-e6ff-4106-8df1-5777f70a98d5-0', 'md5': 'a92669ec8852230a10256ac23bbf4489', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process procdump64.exe was detected by the report "Memory Grab using ProcDump" in watchlist "Carbon Black Community"', 'reputation': 'TRUSTED_WHITE_LIST', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'procdump64.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '16f413862efda3aba631d8a7ae2bfff6d84acd9f454a7adaa518c7a8a6f375a5'}, 'lastUpdatedTime': 0, 'threatId': 'db260acf65984a2c74ae0c41a8e08086', 'summary': 'Memory Grab using ProcDump', 'reputation': 'TRUSTED_WHITE_LIST', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9', 'incidentId': 'WNEXFKQ7-000049d4-00000ac8-00000000-1d4ed590863aac9-n8JQkq8TuqkYoTiT5wObg-47a50561-e6ff-4106-8df1-5777f70a98d5'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651828170, 'eventDescription': '[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06] [T1003 - Credential Dumping #3] [Incident id: WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06] [Threat score: 9] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 9]\n', 'url': 'https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-notification', 'threatHunterInfo': {'responseSeverity': 9, 'reportName': 'T1003 - Credential Dumping #3', 'documentGuid': 'NM1Pn_drQ3airxKooRokmQ', 'runState': 'RAN', 'firstActivityTime': 1554651828170, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 9, 'indicators': [{'applicationName': 'procdump.exe', 'indicatorName': '7aa6e57a-6fa8-423d-b997-427565bf7a06-0', 'sha256Hash': '05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad'}], 'sha256': '05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\downloads\\procdump\\procdump.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': '3ExgIixySwmbRuaXoxxKeA', 'name': 'Carbon Black Advanced Threats'}], 'time': 1554652418279, 'reportId': '1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06', 'responseAlarmId': 'WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06', 'iocId': '7aa6e57a-6fa8-423d-b997-427565bf7a06-0', 'md5': '6a09bc6c19c4236c0bd8a01953371a29', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process procdump.exe was detected by the report "T1003 - Credential Dumping #3" in watchlist "Carbon Black Advanced Threats"', 'reputation': 'TRUSTED_WHITE_LIST', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'procdump.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '05732e84de58a3cc142535431b3aa04efbe034cc96e837f93c360a6387d8faad'}, 'lastUpdatedTime': 0, 'threatId': 'ddb41379ce092f02c635851f4a9364f2', 'summary': 'T1003 - Credential Dumping #3', 'reputation': 'TRUSTED_WHITE_LIST', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9', 'incidentId': 'WNEXFKQ7-000049d4-000011c4-00000000-1d4ed58af5a4ce9-1X7Zx5ZRbGc24xRp7IaQ-7aa6e57a-6fa8-423d-b997-427565bf7a06'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651837865, 'eventDescription': '[sm-sentinel-notification] [Carbon Black has detected a threat against your company.] [https://defense-eap01.conferdeploy.net#device/18900/incident/WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [T1003 - Credential Dumping #2] [Incident id: WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507] [Threat score: 10] [Group: sm-detection] [Email: smultani@carbonblack.com] [Name: win-559j1nqvfgj] [Type and OS: WINDOWS pscr-sensor] [Severity: 10]\n', 'url': 'https://defense-eap01.conferdeploy.net/investigate?s[searchWindow]=ALL&s[c][DEVICE_ID][0]=18900&s[c][INCIDENT_ID][0]=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-notification', 'threatHunterInfo': {'responseSeverity': 10, 'reportName': 'T1003 - Credential Dumping #2', 'documentGuid': 'FtA0ybjVRJuJ2VohA5E-Lw', 'runState': 'RAN', 'firstActivityTime': 1554651837865, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 10, 'indicators': [{'applicationName': 'mimikatz.exe', 'indicatorName': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'sha256Hash': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}], 'sha256': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\music\\mimikatz_trunk (1)\\win32\\mimikatz.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': '3ExgIixySwmbRuaXoxxKeA', 'name': 'Carbon Black Advanced Threats'}], 'time': 1554652418305, 'reportId': '1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'responseAlarmId': 'WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'iocId': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'md5': '9e9ea5e8a16995124ba6e75bad4c6abe', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process mimikatz.exe was detected by the report "T1003 - Credential Dumping #2" in watchlist "Carbon Black Advanced Threats"', 'reputation': 'KNOWN_MALWARE', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'mimikatz.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}, 'lastUpdatedTime': 0, 'threatId': '5f1763e2ea26c424e8a84ec6b1090983', 'summary': 'T1003 - Credential Dumping #2', 'reputation': 'KNOWN_MALWARE', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502', 'incidentId': 'WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507'}, 'type': 'THREAT_HUNTER'}, {'eventTime': 1554651837865, 'eventDescription': '[sm-sentinel-watchlist] [Carbon Black has detected one or more threat indicator(s) on one of your devices.]  [https://defense-eap01.conferdeploy.net/threat-hunter/analyze?processGUID=WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502&deviceId=18900] [T1003 - Credential Dumping #2] [Group: sm-detection] [Device Email: smultani@carbonblack.com] [Device Name: win-559j1nqvfgj] [Device Type: WINDOWS] [IOC: b7e9fd8e-febe-478c-8f44-2e90e0d10507-0] [Severity: 10]', 'url': 'https://defense-eap01.conferdeploy.net', 'deviceInfo': {'deviceName': 'win-559j1nqvfgj', 'deviceHostName': '', 'externalIpAddress': '73.69.152.214', 'deviceId': 18900, 'uemId': '', 'targetPriorityCode': 0, 'internalIpAddress': '192.168.81.148', 'groupName': 'sm-detection', 'deviceType': 'WINDOWS', 'deviceVersion': 'pscr-sensor', 'email': 'smultani@carbonblack.com', 'targetPriorityType': 'MEDIUM'}, 'source': 'test', 'ruleName': 'sm-sentinel-watchlist', 'threatHunterInfo': {'responseSeverity': 10, 'reportName': 'T1003 - Credential Dumping #2', 'documentGuid': 'FtA0ybjVRJuJ2VohA5E-Lw', 'runState': 'RAN', 'firstActivityTime': 1554651837865, 'dismissed': 'false', 'targetPriority': 'MEDIUM', 'score': 10, 'indicators': [{'applicationName': 'mimikatz.exe', 'indicatorName': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'sha256Hash': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}], 'sha256': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be', 'status': 'UNRESOLVED', 'processPath': 'c:\\users\\smultani\\music\\mimikatz_trunk (1)\\win32\\mimikatz.exe', 'tags': '', 'watchLists': [{'alert': 'true', 'id': '3ExgIixySwmbRuaXoxxKeA', 'name': 'Carbon Black Advanced Threats'}], 'time': 1554652418330, 'reportId': '1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'responseAlarmId': 'WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507', 'iocId': 'b7e9fd8e-febe-478c-8f44-2e90e0d10507-0', 'md5': '9e9ea5e8a16995124ba6e75bad4c6abe', 'count': 0, 'threatCause': {'actorProcessPPid': '', 'reason': 'Process mimikatz.exe was detected by the report "T1003 - Credential Dumping #2" in watchlist "Carbon Black Advanced Threats"', 'reputation': 'KNOWN_MALWARE', 'threatCategory': 'RESPONSE_WATCHLIST', 'actorName': 'mimikatz.exe', 'causeEventId': '', 'actorType': '', 'originSourceType': 'UNKNOWN', 'actor': '6a127f8940419938d7aab6e99c85c46d80d273f25e064583771da346aa64b7be'}, 'lastUpdatedTime': 0, 'threatId': '5f1763e2ea26c424e8a84ec6b1090983', 'summary': 'T1003 - Credential Dumping #2', 'reputation': 'KNOWN_MALWARE', 'orgId': 428, 'policyId': 9815, 'processGuid': 'WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502', 'incidentId': 'WNEXFKQ7-000049d4-00001228-00000000-1d4ed58b5502502-1X7Zx5ZRbGc24xRp7IaQ-b7e9fd8e-febe-478c-8f44-2e90e0d10507'}, 'type': 'THREAT_HUNTER'}]