import socket
import ssl
import sys
import argparse
import ConfigParser
import requests
from jinja2 import Template
import os
import json
import time
import logging
import logging.handlers
from cb_defense_syslog import *
import traceback
import hashlib
import fcntl


def notification_server_request(url, siem_api_key, siem_connector_id, ssl_verify, logger, proxies=None):
    logger.info("Attempting to connect to url: " + url)

    headers = {'X-Auth-Token': "{0}/{1}".format(siem_api_key, siem_connector_id)}
    try:
        response = requests.get(url + '/integrationServices/v3/notification', headers=headers, timeout=15,
                                verify=ssl_verify, proxies=proxies)
        logger.info(response)

    except Exception as e:
        logging.error(e, exc_info=True)
        return None

    else:
        return response


def gather_notification_context(url, notification_id, api_key_query, connector_id_query, ssl_verify, logger,  proxies=None):
    try:
        response = requests.get("{0}/integrationServices/v3/alert/{1}".format(url,
                                                                              notification_id),
                                headers={"X-Auth-Token": "{0}/{1}".format(api_key_query,
                                                                          connector_id_query)})
        if response.status_code != 200:
            logger.error("Could not retrieve context for id {0}: {1}".format(notification_id,
                                                                             response.status_code))
            return None

        return response.json()
    except Exception as e:
        logger.exception("Could not retrieve notification context for org id {1}: {2}".format(
            notification_id,
            str(e)))
        return None


def parse_cb_defense_notifications_get_incidentids(response):
    incidentids = []
    for notification in response['notifications']:
        threatinfo = notification.get('threatInfo', None)
        if threatinfo is not None:
            incidentid = threatinfo.get('incidentId', None)
            if incidentid is not None:
                incidentids.append(incidentid)
    return incidentids


def parse_notification_response_leef(response, source, logger):
    # LEEF: 2.0 | Vendor | Product | Version | EventID | xa6 |
    version = 'LEEF:2.0'
    vendor = 'CarbonBlack'
    product = 'CbDefense'
    dev_version = '0.1'
    hex_sep = "x09"
    splitDomain = True

    leef_header = '|'.join([version, vendor, product, dev_version])
    log_messages = []

    success = False

    if response:
        response = response.json()
        success = response.get("success", False)

    if not success:
        return log_messages

    if success:

        if len(response['notifications']) < 1:
            logger.info('successfully connected, no alerts at this time')
            return None
        for note in response['notifications']:
            indicators = []
            current_notification_leef_header = leef_header
            eventId = get_unicode_string(note.get('eventId'))
            kvpairs = {"eventId": eventId}
            devTime = note.get("eventTime", 0)
            devTime = time.strftime('%b-%d-%Y %H:%M:%S GMT', time.gmtime(devTime / 1000))
            devTimeFormat = "MMM dd yyyy HH:mm:ss z"
            url = note.get("url", "noUrlProvided")
            ruleName = note.get("ruleName", "noRuleName")
            kvpairs.update({"devTime": devTime, "devTimeFormat": devTimeFormat, "url": url, "ruleName": ruleName})
            if note.get('type', 'noType') == 'THREAT' or note.get('threatInfo', False):
                current_notification_leef_header += "|{0}|{1}|".format("THREAT", hex_sep)
                cat = "THREAT"
                indicators = note['threatInfo'].get('indicators', [])
                kvpairs.update(note.get("deviceInfo", {}))
                kvpairs.update({"incidentId": note['threatInfo'].get("incidentId", "noIncidentId")})
                signature = 'Active_Threat'
                summary = get_unicode_string(note['threatInfo'].get('summary', ""))
                sev = get_unicode_string(note['threatInfo']['score'])
                device_name = get_unicode_string(note['deviceInfo']['deviceName'])
                email = get_unicode_string(note['deviceInfo']['email'])
                src = get_unicode_string(note['deviceInfo'].get('internalIpAddress', "0.0.0.0"))
                kvpairs.update({"cat": cat, "url": url, "type": "THREAT", "signature": signature, "sev": sev,
                                "resource": device_name, "email": email, "src": src, "identSrc": src, "dst": src,
                                "identHostName": device_name, "summary": summary})

            elif note.get('type', "noType") == 'POLICY_ACTION' or note.get("policyAction", False):
                severity = 1
                summary = get_unicode_string(note['policyAction'].get('summary', ''))
                device_name = get_unicode_string(note['deviceInfo']['deviceName'])
                email = get_unicode_string(note['deviceInfo']['email'])
                src = get_unicode_string(note['deviceInfo'].get('internalIpAddress', "0.0.0.0"))
                sha256 = get_unicode_string(note['policyAction']['sha256Hash'])
                action = note.get('policyAction', {}).get('action', None)
                current_notification_leef_header += "|" + (
                    get_unicode_string(action) if action else "POLICY_ACTION") + "|" + hex_sep + "|"
                app_name = get_unicode_string(note['policyAction']['applicationName'])
                reputation = get_unicode_string(note['policyAction'].get('reputation', ""))
                url = get_unicode_string(note['url'])
                kvpairs.update({"cat": "POLICY_ACTION", "sev": severity, "type": "POLICY_ACTION", "action": action,
                                "reputation": reputation, "resource": device_name, "email": email, "src": src,
                                "dst": src, "identSrc": src, "identHostName": device_name, "summary": summary,
                                "sha256Hash": sha256, "applicationName": app_name, "url": url})

            else:
                continue

            log_messages.append(
                current_notification_leef_header + "\t".join(["{0}={1}".format(k, kvpairs[k]) for k in kvpairs]))

            for indicator in indicators:
                indicator_name = indicator['indicatorName']
                indicator_header = leef_header + "|{0}|{1}|".format(indicator_name, hex_sep)
                indicator_dict = indicator_header + "\t".join(
                    ["{0}={1}".format(k, kvpairs[k]) for k in kvpairs]) + "\t" + "\t".join(
                    ["{0}={1}".format(k, indicator[k]) for k in indicator])
                log_messages.append(indicator_dict)

    return log_messages

def parse_notification_response_json(response, source, logger):
    if u'success' not in response:
        return []

    if response[u'success']:
        if len(response[u'notifications']) < 1:
            logger.info('successfully connected, no alerts at this time')
            return []

        for notification in response[u'notifications']:
            if 'type' not in notification:
                notification['type'] = 'THREAT'
            notification['source'] = source

    return response['notifications']


def parse_notification_response_cef(response, source, logger):
    version = 'CEF:0'
    vendor = 'CarbonBlack'
    product = 'CbDefense_Syslog_Connector'
    dev_version = '2.0'
    splitDomain = True

    log_messages = []

    if u'success' not in response:
        return log_messages

    if response[u'success']:

        if len(response[u'notifications']) < 1:
            logger.info('successfully connected, no alerts at this time')
            return None

        for note in response[u'notifications']:
            if 'type' not in note:
                note['type'] = 'THREAT'

            if note['type'] == 'THREAT':
                signature = 'Active_Threat'
                seconds = get_unicode_string(note['eventTime'])[:-3]
                name = get_unicode_string(note['threatInfo']['summary'])
                severity = get_unicode_string(note['threatInfo']['score'])
                device_name = get_unicode_string(note['deviceInfo']['deviceName'])
                user_name = get_unicode_string(note['deviceInfo']['email'])
                device_ip = get_unicode_string(note['deviceInfo']['internalIpAddress'])
                link = get_unicode_string(note['url'])
                tid = get_unicode_string(note['threatInfo']['incidentId'])
                timestamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
                extension = ''
                extension += 'rt="' + timestamp + '"'

                if '\\' in device_name and splitDomain:
                    (domain_name, device) = device_name.split('\\')
                    extension += ' sntdom=' + domain_name
                    extension += ' dvchost=' + device
                else:
                    extension += ' dvchost=' + device_name

                if '\\' in user_name and splitDomain:
                    (domain_name, user) = user_name.split('\\')
                    extension += ' duser=' + user
                else:
                    extension += ' duser=' + user_name

                extension += ' dvc=' + device_ip
                extension += ' cs3Label="Link"'
                extension += ' cs3="' + link + '"'
                extension += ' cs4Label="Threat_ID"'
                extension += ' cs4="' + tid + '"'
                extension += ' act=Alert'

            elif note['type'] == 'POLICY_ACTION':
                signature = 'Policy_Action'
                name = 'Confer Sensor Policy Action'
                severity = policy_action_severity
                seconds = get_unicode_string(note['eventTime'])[:-3]
                timestamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
                device_name = get_unicode_string(note['deviceInfo']['deviceName'])
                user_name = get_unicode_string(note['deviceInfo']['email'])
                device_ip = get_unicode_string(note['deviceInfo']['internalIpAddress'])
                sha256 = get_unicode_string(note['policyAction']['sha256Hash'])
                action = get_unicode_string(note['policyAction']['action'])
                app_name = get_unicode_string(note['policyAction']['applicationName'])
                link = get_unicode_string(note['url'])
                extension = ''
                extension += 'rt="' + timestamp + '"'
                if '\\' in device_name and splitDomain == True:
                    (domain_name, device) = device_name.split('\\')
                    extension += ' sntdom=' + domain_name
                    extension += ' dvchost=' + device
                else:
                    extension += ' dvchost=' + device_name

                if '\\' in user_name and splitDomain == True:
                    (domain_name, user) = user_name.split('\\')
                    extension += ' duser=' + user
                else:
                    extension += ' duser=' + user_name

                extension += ' dvc=' + device_ip
                extension += ' cs3Label="Link"'
                extension += ' cs3="' + link + '"'
                extension += ' act=' + action
                extension += ' hash=' + sha256
                extension += ' deviceprocessname=' + app_name

            else:
                continue

            log_messages.append({'version': version,
                                 'vendor': vendor,
                                 'product': product,
                                 'dev_version': dev_version,
                                 'signature': signature,
                                 'name': name,
                                 'severity': severity,
                                 'extension': extension,
                                 'source': source})
    return log_messages