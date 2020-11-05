# -*- coding: utf-8 -*-


null = ""
true = "true"
false = "false"


test_data_audit = {
    "notifications": [
        {
            "requestUrl": null,
            "eventTime": 1529332687006,
            "eventId": "37075c01730511e89504c9ba022c3fbf",
            "loginName": "bs@carbonblack.com",
            "orgName": "example.org",
            "flagged": false,
            "clientIp": "192.0.2.3",
            "verbose": false,
            "description": "Logged in successfully"
        },
        {
            "requestUrl": null,
            "eventTime": 1529332689528,
            "eventId": "38882fa2730511e89504c9ba022c3fbf",
            "loginName": "bs@carbonblack.com",
            "orgName": "example.org",
            "flagged": false,
            "clientIp": "192.0.2.3",
            "verbose": false,
            "description": "Logged in successfully"
        },
        {
            "requestUrl": null,
            "eventTime": 1529345346615,
            "eventId": "b0be64fd732211e89504c9ba022c3fbf",
            "loginName": "bs@carbonblack.com",
            "orgName": "example.org",
            "flagged": false,
            "clientIp": "192.0.2.1",
            "verbose": false,
            "description": "Updated connector jason-splunk-test with api key Y8JNJZFBDRUJ2ZSM"
        },
        {
            "requestUrl": null,
            "eventTime": 1529345352229,
            "eventId": "b41705e7732211e8bd7e5fdbf9c916a3",
            "loginName": "bs@carbonblack.com",
            "orgName": "example.org",
            "flagged": false,
            "clientIp": "192.0.2.2",
            "verbose": false,
            "description": "Updated connector Training with api key GRJSDHRR8YVRML3Q"
        },
        {
            "requestUrl": null,
            "eventTime": 1529345371514,
            "eventId": "bf95ae38732211e8bd7e5fdbf9c916a3",
            "loginName": "bs@carbonblack.com",
            "orgName": "example.org",
            "flagged": false,
            "clientIp": "192.0.2.2",
            "verbose": false,
            "description": "Logged in successfully"
        }
    ],
    "success": true,
    "message": "Success"
}


cef_output_audit = ['test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Audit Logs|Logged in successfully|1|rt="Jun 18 2018 14:38:07" dvchost=example.org duser=bs@carbonblack.com dvc=192.0.2.3 cs3Label="Link" cs3="" cs4Label="Threat_ID" cs4="37075c01730511e89504c9ba022c3fbf" deviceprocessname=PSC act=Alert', 'test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Audit Logs|Logged in successfully|1|rt="Jun 18 2018 14:38:09" dvchost=example.org duser=bs@carbonblack.com dvc=192.0.2.3 cs3Label="Link" cs3="" cs4Label="Threat_ID" cs4="38882fa2730511e89504c9ba022c3fbf" deviceprocessname=PSC act=Alert', 'test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Audit Logs|Updated connector jason-splunk-test with api key Y8JNJZFBDRUJ2ZSM|1|rt="Jun 18 2018 18:09:06" dvchost=example.org duser=bs@carbonblack.com dvc=192.0.2.1 cs3Label="Link" cs3="" cs4Label="Threat_ID" cs4="b0be64fd732211e89504c9ba022c3fbf" deviceprocessname=PSC act=Alert', 'test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Audit Logs|Updated connector Training with api key GRJSDHRR8YVRML3Q|1|rt="Jun 18 2018 18:09:12" dvchost=example.org duser=bs@carbonblack.com dvc=192.0.2.2 cs3Label="Link" cs3="" cs4Label="Threat_ID" cs4="b41705e7732211e8bd7e5fdbf9c916a3" deviceprocessname=PSC act=Alert', 'test CEF:0|CarbonBlack|CbDefense_Syslog_Connector|2.0|Audit Logs|Logged in successfully|1|rt="Jun 18 2018 18:09:31" dvchost=example.org duser=bs@carbonblack.com dvc=192.0.2.2 cs3Label="Link" cs3="" cs4Label="Threat_ID" cs4="bf95ae38732211e8bd7e5fdbf9c916a3" deviceprocessname=PSC act=Alert']


leef_output_audit = ['LEEF:2.0|CarbonBlack|CbDefense|0.1|AUDIT|x09|cat=AUDIT\tdevTime=Jun-18-2018 14:38:07 GMT\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\teventId=37075c01730511e89504c9ba022c3fbf\tloginName=bs@carbonblack.com\torgName=example.org\tsrc=192.0.2.3\tsummary=Logged in successfully', 'LEEF:2.0|CarbonBlack|CbDefense|0.1|AUDIT|x09|cat=AUDIT\tdevTime=Jun-18-2018 14:38:09 GMT\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\teventId=38882fa2730511e89504c9ba022c3fbf\tloginName=bs@carbonblack.com\torgName=example.org\tsrc=192.0.2.3\tsummary=Logged in successfully', 'LEEF:2.0|CarbonBlack|CbDefense|0.1|AUDIT|x09|cat=AUDIT\tdevTime=Jun-18-2018 18:09:06 GMT\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\teventId=b0be64fd732211e89504c9ba022c3fbf\tloginName=bs@carbonblack.com\torgName=example.org\tsrc=192.0.2.1\tsummary=Updated connector jason-splunk-test with api key Y8JNJZFBDRUJ2ZSM', 'LEEF:2.0|CarbonBlack|CbDefense|0.1|AUDIT|x09|cat=AUDIT\tdevTime=Jun-18-2018 18:09:12 GMT\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\teventId=b41705e7732211e8bd7e5fdbf9c916a3\tloginName=bs@carbonblack.com\torgName=example.org\tsrc=192.0.2.2\tsummary=Updated connector Training with api key GRJSDHRR8YVRML3Q', 'LEEF:2.0|CarbonBlack|CbDefense|0.1|AUDIT|x09|cat=AUDIT\tdevTime=Jun-18-2018 18:09:31 GMT\tdevTimeFormat=MMM dd yyyy HH:mm:ss z\teventId=bf95ae38732211e8bd7e5fdbf9c916a3\tloginName=bs@carbonblack.com\torgName=example.org\tsrc=192.0.2.2\tsummary=Logged in successfully']

json_output_audit = [{'requestUrl': '', 'eventTime': 1529332687006, 'eventId': '37075c01730511e89504c9ba022c3fbf', 'loginName': 'bs@carbonblack.com', 'orgName': 'example.org', 'flagged': 'false', 'clientIp': '192.0.2.3', 'verbose': 'false', 'description': 'Logged in successfully', 'type': 'AUDIT', 'source': 'test'}, {'requestUrl': '', 'eventTime': 1529332689528, 'eventId': '38882fa2730511e89504c9ba022c3fbf', 'loginName': 'bs@carbonblack.com', 'orgName': 'example.org', 'flagged': 'false', 'clientIp': '192.0.2.3', 'verbose': 'false', 'description': 'Logged in successfully', 'type': 'AUDIT', 'source': 'test'}, {'requestUrl': '', 'eventTime': 1529345346615, 'eventId': 'b0be64fd732211e89504c9ba022c3fbf', 'loginName': 'bs@carbonblack.com', 'orgName': 'example.org', 'flagged': 'false', 'clientIp': '192.0.2.1', 'verbose': 'false', 'description': 'Updated connector jason-splunk-test with api key Y8JNJZFBDRUJ2ZSM', 'type': 'AUDIT', 'source': 'test'}, {'requestUrl': '', 'eventTime': 1529345352229, 'eventId': 'b41705e7732211e8bd7e5fdbf9c916a3', 'loginName': 'bs@carbonblack.com', 'orgName': 'example.org', 'flagged': 'false', 'clientIp': '192.0.2.2', 'verbose': 'false', 'description': 'Updated connector Training with api key GRJSDHRR8YVRML3Q', 'type': 'AUDIT', 'source': 'test'}, {'requestUrl': '', 'eventTime': 1529345371514, 'eventId': 'bf95ae38732211e8bd7e5fdbf9c916a3', 'loginName': 'bs@carbonblack.com', 'orgName': 'example.org', 'flagged': 'false', 'clientIp': '192.0.2.2', 'verbose': 'false', 'description': 'Logged in successfully', 'type': 'AUDIT', 'source': 'test'}]
