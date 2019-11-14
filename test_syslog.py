#!/usr/bin/env python

from test.test_data import *
import audit_log as al
import notifications as n
import unittest
from jinja2 import Template
import logging
import logging.handlers
import json

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

from six import PY2

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

    def test_cef_notifications(self):
        response_notification = n.parse_response_cef(test_data_notification, "test", logger, get_unicode_string)

        template = Template(
            "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        output_notifications = "\n".join([template.render(log).encode('utf8') for log in response_notification])

        self.assertEqual(output_notifications, cef_output_notification)

    def test_leef_notifications(self):
        template = Template("{{source}}:{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{eventid}}|{{hex_sep}}|{{extension}}")
        response_notification = n.parse_response_leef(test_data_notification, "test", logger, get_unicode_string)

        final_data = ''
        for log in response_notification:
            final_data = final_data + log + "\n"

        #self.assertEqual(final_data, cef_output_notification)

    def test_json_notifications(self):
        response_notification = n.parse_response_json(test_data_notification, "test", logger, get_unicode_string)
        final_data = json.dumps(response_notification) + '\n'

        self.assertEqual(final_data, json_output_notification)

    def test_cef_audit(self):
        response_notification = al.parse_response_cef(test_data_audit, "test", logger, get_unicode_string)
        # responses_audit = al.parse_response_cef(test_data_audit, "test")

        template = Template(
            "{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        output_audit = "\n".join([template.render(log).encode('utf8') for log in response_notification])

        self.assertEqual(output_audit, cef_output_audit)

    def test_leef_audit(self):
        template = Template(
            "{{source}}:{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{eventid}}|{{hex_sep}}|{{extension}}")
        response_notification = al.parse_response_leef(test_data_audit, "test", logger, get_unicode_string)

        final_data = ''
        for log in response_notification:
            final_data = final_data + log + "\n"

        self.assertEqual(final_data, leef_output_audit)

    def test_json_audit(self):
        response_notification = al.parse_response_json(test_data_notification, "test", logger, get_unicode_string)
        final_data = json.dumps(response_notification) + '\n'

        # self.assertEqual(str(final_data), json_output_notification)


if __name__ == '__main__':
    unittest.main()