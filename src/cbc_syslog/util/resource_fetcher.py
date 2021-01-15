from .six import PY2
from .audit_log import (audit_log_server_request,
                            parse_audit_log_json,
                            parse_audit_log_cef,
                            parse_audit_log_leef)

from .notifications import (notification_server_request,
                                parse_notification_json,
                                parse_notification_cef,
                                parse_notification_leef)

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str


def fetch_notification_logs(server, output_format, policy_action_severity=1):
    notification_response = notification_server_request(server.get('server_url'),
                                                        server.get('siem_api_key'),
                                                        server.get('siem_connector_id'),
                                                        server.get('https_ssl_verify'))
    if notification_response is None:
        logger.warn(
            "Received unexpected (or no) response from Carbon Black Cloud Server {0}.".format(
                server.get('server_url')))
        return None
    else:
        notification_json = notification_response.json()

        if output_format == 'json':
            notifications_logs = parse_notification_json(notification_json,
                                                         server.get('server_url'),
                                                         get_unicode_string)
        elif output_format == 'leef':
            notifications_logs = parse_notification_leef(notification_json,
                                                         server.get('server_url'),
                                                         get_unicode_string,
                                                         policy_action_severity)
        else:
            notifications_logs = parse_notification_cef(notification_json,
                                                        server.get('server_url'),
                                                        get_unicode_string,
                                                        policy_action_severity)
        return notifications_logs


def fetch_audit_logs(server, output_format):
    audit_response = audit_log_server_request(server.get('server_url'),
                                              server.get('api_key'),
                                              server.get('api_connector_id'),
                                              server.get('https_ssl_verify'))

    if audit_response is None:
        logger.warn(
            "Received unexpected (or no) response from Carbon Black Server {0}.".format(
                server.get('server_url')))
        return None
    else:
        audit_json = audit_response.json()

        if output_format == 'json':
            audit_logs = parse_audit_log_json(audit_json, server.get('server_url'), get_unicode_string)
        elif output_format == 'leef':
            audit_logs = parse_audit_log_leef(audit_json, server.get('server_url'), get_unicode_string)
        else:
            audit_logs = parse_audit_log_cef(audit_json, server.get('server_url'), get_unicode_string)

        return audit_logs
