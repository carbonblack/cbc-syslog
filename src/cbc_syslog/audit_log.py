import requests
import logging
import time

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def get_audit_logs(url, api_key_query, api_connector_id_query, ssl_verify, proxies=None):
    headers = {'X-Auth-Token': "{0}/{1}".format(api_key_query, api_connector_id_query)}
    try:
        response = requests.get("{0}/integrationServices/v3/auditlogs".format(url),
                                headers=headers,
                                timeout=15, proxies=proxies)

        if response.status_code != 200:
            logger.error("Could not retrieve audit logs: {0}".format(response.status_code))
            return None

        notifications = response.json()

    except Exception as e:
        logger.error("Exception {0} when retrieving audit logs".format(get_unicode_string(e)), exc_info=True)
        return None

    if notifications.get("success", False) != True:
        logger.error("Unsuccessful HTTP response retrieving audit logs: {0}"
                     .format(notifications.get("message")))
        return None

    notifications = notifications.get("notifications", [])
    if not notifications:
        logger.info("No audit logs available")
        return None

    return response


def parse_response_cef(response, source, get_unicode_string):
    version = 'CEF:0'
    vendor = 'CarbonBlack'
    product = 'CbDefense_Syslog_Connector'
    dev_version = '2.0'
    application = 'PSC'
    splitDomain = True
    severity = '1'

    log_messages = []

    for audits in response[u'notifications']:

        signature = 'Audit Logs'
        seconds = get_unicode_string(audits['eventTime'])[:-3]
        name = get_unicode_string(audits['description'])
        device_name = get_unicode_string(audits['orgName'])
        user_name = get_unicode_string(audits['loginName'])
        device_ip = get_unicode_string(audits['clientIp'])
        link = get_unicode_string(audits['requestUrl'])
        tid = get_unicode_string(audits['eventId'])
        timestamp = time.strftime("%b %d %Y %H:%M:%S", time.gmtime(int(seconds)))
        app_name = application
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
        extension += ' deviceprocessname=' + app_name
        extension += ' act=Alert'

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


def parse_response_leef(response, source, get_unicode_string):
    # LEEF: 2.0 | Vendor | Product | Version | EventID | xa6 |
    version = 'LEEF:2.0'
    vendor = 'CarbonBlack'
    product = 'CbDefense'
    dev_version = '0.1'
    hex_sep = "x09"
    splitDomain = True

    leef_header = '|'.join([version, vendor, product, dev_version])
    log_messages = []


    for audits in response['notifications']:
        severity = 1

        indicators = []
        current_notification_leef_header = leef_header
        eventId = get_unicode_string(audits.get('eventId')).encode("utf-8").strip()
        kvpairs = {"eventId": eventId}
        devTime = audits.get("eventTime", 0)
        devTime = time.strftime('%b-%d-%Y %H:%M:%S GMT', time.gmtime(devTime / 1000))
        devTimeFormat = "MMM dd yyyy HH:mm:ss z"
        url = audits.get("requestUrl", "noUrlProvided")
        app_name = get_unicode_string('Syslog').encode("utf-8").strip()
        kvpairs.update({"devTime": devTime, "devTimeFormat": devTimeFormat, "url": url})

        current_notification_leef_header += "|{0}|{1}|".format("PSC", hex_sep)
        cat = "PSC"
        indicators = audits.get('indicators', [])
        signature = 'Active_Threat'
        summary = get_unicode_string(audits.get('summary', "")).encode("utf-8").strip()
        device_name = get_unicode_string(audits['orgName']).encode("utf-8").strip()
        email = get_unicode_string(audits['loginName']).encode("utf-8").strip()
        src = get_unicode_string(audits.get('internalIpAddress', "0.0.0.0")).encode("utf-8").strip()
        kvpairs.update({"cat": cat, "url": url, "type": "THREAT", "signature": signature,
                        "resource": device_name, "email": email, "src": src, "identSrc": src, "dst": src,
                        "identHostName": device_name, "summary": summary})

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

def parse_response_json(response, source, get_unicode_string):

    for notification in response[u'notifications']:
        notification['type'] = 'AUDIT'
        notification['source'] = source

    return response['notifications']
