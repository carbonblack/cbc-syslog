#!/usr/bin/env python

from test.test_data import *
from test.test_data_threathunter import *
from test.test_data_audit import *
from src.cb_defense_syslog import audit_log as al, notifications as n
import unittest
from jinja2 import Template
import logging.handlers
import json

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

from src.cb_defense_syslog.six import PY2

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
        response_notification = n.parse_response_cef_psc(test_data_notification, "test", get_unicode_string)

        template = Template(
            "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        output_notifications = "\n".join([template.render(log).encode('utf8') for log in response_notification])

        self.assertEqual(output_notifications, cef_output_notification)

    def test_leef_notifications_psc(self):
        template = Template("{{source}}:{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{eventid}}|{{hex_sep}}|{{extension}}")
        response_notification = n.parse_response_leef_psc(test_data_notification, "test", get_unicode_string)
        final_data = ''
        for log in response_notification:
            final_data = final_data + log + "\n"

        self.assertEqual(response_notification, leef_output_notification)

    def test_json_notifications_psc(self):

        response_notification = n.parse_response_json_psc(test_data_notification, "test", get_unicode_string)
        final_data = json.dumps(response_notification, sort_keys=True) + '\n'
        final_data_test = json.dumps(json_output_notification, sort_keys=True) + '\n'

        self.assertEqual(final_data, final_data_test)

    def test_cef_notifications_threat_hunter(self):
        response_notification = n.parse_response_cef_psc(test_data_threat_hunter, "test", get_unicode_string)

        template = Template(
            "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        output_notifications = "\n".join([template.render(log).encode('utf8') for log in response_notification])

        self.assertEqual(output_notifications, cef_output_notification_th)

    def test_leef_notifications_threat_hunter(self):
        template = Template("{{source}}:{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{eventid}}|{{hex_sep}}|{{extension}}")
        response_notification = n.parse_response_leef_psc(test_data_threat_hunter, "test", get_unicode_string)

        final_data = ''
        for log in response_notification:
            final_data = final_data + log + "\n"

        self.assertEqual(final_data, leef_output_notification_th)

    def test_json_notifications_threat_hunter(self):
        response_notification = n.parse_response_json_psc(test_data_threat_hunter, "test", get_unicode_string)
        final_data = json.dumps(response_notification, sort_keys=True) + '\n'
        final_data_test = json.dumps(json_output_notification_th, sort_keys=True) + '\n'

        self.assertEqual(final_data, final_data_test)

    def test_cef_audit_psc(self):
        response_notification = al.parse_response_cef(test_data_audit, "test", get_unicode_string)
        # responses_audit = al.parse_response_cef(test_data_audit, "test")

        template = Template(
            "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        output_audit = "\n".join([template.render(log).encode('utf8') for log in response_notification])

        self.assertEqual(output_audit, cef_output_audit)

    def test_leef_audit_psc(self):
        template = Template(
            "{{source}}:{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{eventid}}|{{hex_sep}}|{{extension}}")
        response_notification = al.parse_response_leef(test_data_audit, "test", get_unicode_string)

        final_data = ''
        for log in response_notification:
            final_data = final_data + log + "\n"

        self.assertEqual(final_data, leef_output_audit)

    def test_json_audit_psc(self):
        response_notification = al.parse_response_json(test_data_notification, "test", get_unicode_string)
        final_data = json.dumps(response_notification, sort_keys=True) + '\n'
        final_data_test = json.dumps(json_output_audit, sort_keys=True) + '\n'

        self.assertEqual(str(final_data), final_data_test)


if __name__ == '__main__':
    unittest.main()