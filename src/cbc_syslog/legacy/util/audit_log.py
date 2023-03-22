import requests
import logging
import time

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def audit_log_server_request(url, api_key_query, api_connector_id_query, ssl_verify, proxies=None):
    logger.info("Attempting to connect to url: " + url)

    headers = {'X-Auth-Token': "{0}/{1}".format(api_key_query, api_connector_id_query)}
    try:
        response = requests.get("{0}/integrationServices/v3/auditlogs".format(url),
                                headers=headers, timeout=15, verify=ssl_verify, proxies=proxies)

        if response.status_code != 200:
            logger.error("Could not retrieve audit logs: {0}".format(response.status_code))
            return None

        notifications = response.json()

        if not notifications.get("success", False):
            logger.error("Unsuccessful HTTP response retrieving audit logs: {0}"
                         .format(notifications.get("message")))
            return None

    except Exception as e:
        logger.error("Exception {0} when retrieving audit logs".format(e), exc_info=True)
        return None

    return response


def parse_audit_log_cef(response, source, get_unicode_string):
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


def parse_audit_log_leef(response, source, get_unicode_string):
    # LEEF: 2.0 | Vendor | Product | Version | EventID | xa6 |
    version = 'LEEF:2.0'
    vendor = 'CarbonBlack'
    product = 'CbDefense'
    dev_version = '0.1'
    hex_sep = "x09"

    leef_header = '|'.join([version, vendor, product, dev_version])
    log_messages = []

    for audit in response['notifications']:

        current_notification_leef_header = leef_header
        kvpairs = {"eventId": get_unicode_string(audit.get('eventId'))}
        kvpairs['devTime'] = time.strftime('%b-%d-%Y %H:%M:%S GMT', time.gmtime(audit.get("eventTime", 0) / 1000))
        kvpairs['devTimeFormat'] = "MMM dd yyyy HH:mm:ss z"

        current_notification_leef_header += "|{0}|{1}|".format("AUDIT", hex_sep)
        kvpairs['cat'] = "AUDIT"
        kvpairs['loginName'] = get_unicode_string(audit.get('loginName'))
        kvpairs['orgName'] = get_unicode_string(audit.get('orgName'))
        kvpairs['src'] = get_unicode_string(audit.get('clientIp'))

        kvpairs["summary"] = audit.get("description", "<unknown>")
        if len(kvpairs["summary"]) > 1000:
            kvpairs["summary"] = kvpairs["summary"][:1000] + ' [truncated]'

        audit_log = current_notification_leef_header + "\t".join(
            ["{0}={1}".format(k, kvpairs[k]) for k in sorted(kvpairs.keys())])

        log_messages.append(audit_log)

    return log_messages


def parse_audit_log_json(response, source, get_unicode_string):

    for notification in response[u'notifications']:
        notification['type'] = 'AUDIT'
        notification['source'] = source

    return response['notifications']
