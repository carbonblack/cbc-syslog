import requests
import time
import logging

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def notification_server_request(url, siem_api_key, siem_connector_id, ssl_verify, proxies=None):
    logger.info("Attempting to connect to url: " + url)

    headers = {'X-Auth-Token': "{0}/{1}".format(siem_api_key, siem_connector_id)}
    try:
        response = requests.get("{0}/integrationServices/v3/notification".format(url),
                                headers=headers, timeout=15, verify=ssl_verify, proxies=proxies)

        if response.status_code != 200:
            logger.error("Could not retrieve notifications: {0}".format(response.status_code))
            return None

        notifications = response.json()

        if not notifications.get("success", False):
            logger.error("Unsuccessful HTTP response retrieving notifications: {0}"
                         .format(notifications.get("message")))
            return None

    except Exception as e:
        logger.error(e, exc_info=True)
        return None

    else:
        return response


def parse_notification_leef(response, source, get_unicode_string, policy_action_severity=1):
    # LEEF: 2.0 | Vendor | Product | Version | EventID | x09 | Extension
    version = 'LEEF:2.0'
    vendor = 'CarbonBlack'
    product = 'Cloud'
    dev_version = '1.0'
    hex_sep = "x09"

    leef_header = '|'.join([version, vendor, product, dev_version])
    log_messages = []

    if response[u'success']:

        if len(response[u'notifications']) < 1:
            logger.info('successfully connected, no alerts at this time')
            return None
        for note in response[u'notifications']:
            current_notification_leef_header = leef_header
            kvpairs = {"eventId": get_unicode_string(note.get('eventId'))}
            kvpairs['devTime'] = time.strftime('%b-%d-%Y %H:%M:%S GMT', time.gmtime(note.get("eventTime", 0) / 1000))
            kvpairs['devTimeFormat'] = "MMM dd yyyy HH:mm:ss z"
            kvpairs['url'] = note.get("url", "")
            kvpairs['ruleName'] = note.get("ruleName", "noRuleName")

            if note.get('type', None) == 'THREAT' or note.get('threatInfo', False):
                current_notification_leef_header += "|{0}|{1}|".format("THREAT", hex_sep)
                kvpairs['cat'] = "THREAT"
                kvpairs['incidentId'] = note['threatInfo'].get("incidentId", "")
                kvpairs['summary'] = get_unicode_string(note['threatInfo'].get('summary', ""))
                kvpairs['sev'] = get_unicode_string(note['threatInfo']['score'])
                kvpairs['deviceId'] = get_unicode_string(note['deviceInfo']['deviceId'])
                kvpairs['deviceType'] = get_unicode_string(note['deviceInfo']['deviceType'])
                kvpairs['resource'] = get_unicode_string(note['deviceInfo']['deviceName'])
                kvpairs['realm'] = get_unicode_string(note['deviceInfo']['groupName'])
                kvpairs['identSrc'] = get_unicode_string(note['deviceInfo'].get('internalIpAddress', "0.0.0.0"))
                kvpairs['identHostName'] = get_unicode_string(note['deviceInfo'].get('deviceHostName', ""))
                kvpairs['targetPriorityType'] = get_unicode_string(note['deviceInfo']['targetPriorityType'])

                for indicator in note['threatInfo'].get("indicators", []):
                    indicator["sev"] = kvpairs['incidentId']
                    indicator["cat"] = "INDICATOR"
                    indicator["incidentId"] = kvpairs['incidentId']

                    indicator_header = leef_header + "|{0}|{1}|".format('INDICATOR', hex_sep)
                    indicator_log = indicator_header + "\t".join(
                        ["{0}={1}".format(k, indicator[k]) for k in sorted(indicator.keys())])
                    log_messages.append(indicator_log)

            elif note.get('type', None) == 'POLICY_ACTION' or note.get("policyAction", False):
                current_notification_leef_header += "|{0}|{1}|".format("POLICY_ACTION", hex_sep)
                kvpairs['cat'] = "POLICY_ACTION"
                kvpairs['sev'] = policy_action_severity
                kvpairs['summary'] = get_unicode_string(note['policyAction'].get('summary', ""))
                kvpairs['deviceId'] = get_unicode_string(note['deviceInfo']['deviceId'])
                kvpairs['deviceType'] = get_unicode_string(note['deviceInfo']['deviceType'])
                kvpairs['resource'] = get_unicode_string(note['deviceInfo']['deviceName'])
                kvpairs['realm'] = get_unicode_string(note['deviceInfo']['groupName'])
                kvpairs['identSrc'] = get_unicode_string(note['deviceInfo'].get('internalIpAddress', "0.0.0.0"))
                kvpairs['identHostName'] = get_unicode_string(note['deviceInfo'].get('deviceHostName', ""))
                kvpairs['targetPriorityType'] = get_unicode_string(note['deviceInfo']['targetPriorityType'])

                kvpairs['sha256'] = get_unicode_string(note['policyAction']['sha256Hash'])
                kvpairs['action'] = get_unicode_string(note['policyAction']['action'])
                kvpairs['applicationName'] = get_unicode_string(note['policyAction']['applicationName'])
                kvpairs['reputation'] = get_unicode_string(note['policyAction'].get('reputation', ""))

            elif note.get('type', None) == 'THREAT_HUNTER':

                current_notification_leef_header += "|{0}|{1}|".format("THREAT_HUNTER", hex_sep)
                kvpairs['cat'] = "THREAT_HUNTER"
                kvpairs['incidentId'] = note['threatHunterInfo'].get("incidentId", "")
                kvpairs['sev'] = get_unicode_string(note['threatHunterInfo']['score'])
                kvpairs['summary'] = get_unicode_string(note['threatHunterInfo'].get('summary', ""))
                kvpairs['deviceId'] = get_unicode_string(note['deviceInfo']['deviceId'])
                kvpairs['deviceType'] = get_unicode_string(note['deviceInfo']['deviceType'])
                kvpairs['resource'] = get_unicode_string(note['deviceInfo']['deviceName'])
                kvpairs['realm'] = get_unicode_string(note['deviceInfo']['groupName'])
                kvpairs['identSrc'] = get_unicode_string(note['deviceInfo'].get('internalIpAddress', "0.0.0.0"))
                kvpairs['identHostName'] = get_unicode_string(note['deviceInfo'].get('deviceHostName', ""))
                kvpairs['targetPriorityType'] = get_unicode_string(note['deviceInfo']['targetPriorityType'])

                kvpairs['reputation'] = get_unicode_string(note['threatHunterInfo'].get('reputation', ""))
                kvpairs["watchlists"] = ""
                for watchlist in note['threatHunterInfo'].get("watchLists", []):
                    kvpairs["watchlists"] = watchlist["name"] + ", " + kvpairs["watchlists"]
                kvpairs["watchlists"] = kvpairs["watchlists"][:-2]
                kvpairs['reportName'] = get_unicode_string(note['threatHunterInfo']['reportName'])
                kvpairs['sha256'] = get_unicode_string(note['threatHunterInfo']['sha256'])
                kvpairs['runState'] = get_unicode_string(note['threatHunterInfo']['runState'])
                kvpairs['processGuid'] = get_unicode_string(note['threatHunterInfo']['processGuid'])
                kvpairs['processPath'] = get_unicode_string(note['threatHunterInfo']['processPath'])

                for indicator in note['threatHunterInfo'].get("indicators", []):
                    indicator["sev"] = kvpairs['incidentId']
                    indicator["cat"] = "INDICATOR"
                    indicator["incidentId"] = kvpairs['incidentId']

                    indicator_header = leef_header + "|{0}|{1}|".format('INDICATOR', hex_sep)
                    indicator_log = indicator_header + "\t".join(
                        ["{0}={1}".format(k, indicator[k]) for k in sorted(indicator.keys())])
                    log_messages.append(indicator_log)

            else:
                # Unknown notification type
                continue

            leef_log = current_notification_leef_header + "\t".join(
                ["{0}={1}".format(k, kvpairs[k]) for k in sorted(kvpairs.keys())])
            log_messages.append(leef_log)

    return log_messages


def parse_notification_cef(response, source, get_unicode_string, policy_action_severity=1):
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
                extension += ' act=' + action
                extension += ' hash=' + sha256
                extension += ' deviceprocessname=' + app_name

            elif note['type'] == 'THREAT_HUNTER':

                signature = 'Threat_Hunter'
                seconds = get_unicode_string(note['eventTime'])[:-3]
                name = get_unicode_string(note["threatHunterInfo"]['summary'])
                severity = get_unicode_string(note["threatHunterInfo"]['score'])
                device_name = get_unicode_string(note['deviceInfo']['deviceName'])
                user_name = get_unicode_string(note['deviceInfo']['email'])
                device_ip = get_unicode_string(note['deviceInfo']['internalIpAddress'])
                link = get_unicode_string(note['url'])
                tid = get_unicode_string(note["threatHunterInfo"]['incidentId'])
                timestamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
                sha256 = get_unicode_string(note["threatHunterInfo"]['sha256'])

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
                    extension += ' hash=' + sha256

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


def parse_notification_json(response, source, get_unicode_string):
    def encode_decode():
        pass

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
