#!/usr/bin/env python

import json
import logging.handlers
import unittest

from .test_data import (test_data_notification, leef_output_notification,
                        json_output_notification, cef_output_notification)
from .test_data_threathunter import (test_data_threat_hunter, leef_output_notification_th,
                                     json_output_notification_th, cef_output_notification_th)
from .test_data_audit import test_data_audit, leef_output_audit, json_output_audit, cef_output_audit
from cbc_syslog.audit_log import parse_response_json, parse_response_cef, parse_response_leef
from cbc_syslog.notifications import parse_response_json_psc, parse_response_cef_psc, parse_response_leef_psc
from cbc_syslog.six import PY2
from jinja2 import Template

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str


class TestCbDefenseSyslogConnector(unittest.TestCase):

    def setUp(self):
        super(TestCbDefenseSyslogConnector, self).setUp()
        self.addTypeEqualityFunc(str, self.assertMultiLineEqual)
        self.addTypeEqualityFunc(dict, self.assertDictEqual)
        self.addTypeEqualityFunc(list, self.assertListEqual)
        self.addTypeEqualityFunc(tuple, self.assertTupleEqual)
        self.addTypeEqualityFunc(set, self.assertSetEqual)
        self.addTypeEqualityFunc(frozenset, self.assertSetEqual)
        self.maxDiff = None

    def test_cef_notifications_psc(self):
        response_notification = parse_response_cef_psc(test_data_notification, "test", get_unicode_string)

        template = Template(
            "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        output_notifications = "\n".join([template.render(log) for log in response_notification])

        self.assertEqual(output_notifications, cef_output_notification)

    def test_leef_notifications_psc(self):
        response_notification = parse_response_leef_psc(test_data_notification, "test", get_unicode_string)
        final_data = ''
        for log in response_notification:
            final_data = final_data + log + "\n"

        self.assertEqual(response_notification, leef_output_notification)

    def test_json_notifications_psc(self):

        response_notification = parse_response_json_psc(test_data_notification, "test", get_unicode_string)
        final_data = response_notification
        final_data_test = json_output_notification

        self.assertListEqual(final_data, final_data_test)

    def test_cef_notifications_threat_hunter(self):
        response_notification = parse_response_cef_psc(test_data_threat_hunter, "test", get_unicode_string)

        template = Template(
            "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        output_notifications = "\n".join([template.render(log) for log in response_notification])

        self.assertEqual(output_notifications, cef_output_notification_th)

    def test_leef_notifications_threat_hunter(self):
        response_notification = parse_response_leef_psc(test_data_threat_hunter, "test", get_unicode_string)

        final_data = ''
        for log in response_notification:
            final_data = final_data + log + "\n"

        self.assertEqual(final_data, leef_output_notification_th)

    def test_json_notifications_threat_hunter(self):
        response_notification = parse_response_json_psc(test_data_threat_hunter, "test", get_unicode_string)
        final_data = json.dumps(response_notification, sort_keys=True) + '\n'
        final_data_test = json.dumps(json_output_notification_th, sort_keys=True) + '\n'

        self.assertEqual(final_data, final_data_test)

    def test_cef_audit_psc(self):
        response_notification = parse_response_cef(test_data_audit, "test", get_unicode_string)
        # responses_audit = parse_response_cef(test_data_audit, "test")

        template = Template(
            "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        output_audit = "\n".join([template.render(log) for log in response_notification])

        self.assertEqual(output_audit, cef_output_audit)

    def test_leef_audit_psc(self):
        response_notification = parse_response_leef(test_data_audit, "test", get_unicode_string)

        final_data = ''
        for log in response_notification:
            final_data = final_data + log + "\n"

        self.assertEqual(final_data, leef_output_audit)

    def test_json_audit_psc(self):
        response_notification = parse_response_json(test_data_notification, "test", get_unicode_string)
        final_data = json.dumps(response_notification, sort_keys=True) + '\n'
        final_data_test = json.dumps(json_output_audit, sort_keys=True) + '\n'

        self.assertEqual(str(final_data), final_data_test)


if __name__ == '__main__':
    unittest.main()
