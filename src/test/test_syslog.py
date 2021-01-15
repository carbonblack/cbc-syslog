#!/usr/bin/env python
import logging.handlers
import unittest

from .test_data import raw_notifications, cef_notifications, leef_notifications, json_notifications
from .test_data_audit import test_data_audit, cef_output_audit, leef_output_audit, json_output_audit
from cbc_syslog.util.audit_log import parse_audit_log_json, parse_audit_log_cef, parse_audit_log_leef
from cbc_syslog.util.notifications import parse_notification_json, parse_notification_cef, parse_notification_leef
from cbc_syslog.util.six import PY2
from jinja2 import Template

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str


class TestCBCSyslogConnector(unittest.TestCase):

    def setUp(self):
        super(TestCBCSyslogConnector, self).setUp()
        self.addTypeEqualityFunc(str, self.assertMultiLineEqual)
        self.addTypeEqualityFunc(dict, self.assertDictEqual)
        self.addTypeEqualityFunc(list, self.assertListEqual)
        self.addTypeEqualityFunc(tuple, self.assertTupleEqual)
        self.addTypeEqualityFunc(set, self.assertSetEqual)
        self.addTypeEqualityFunc(frozenset, self.assertSetEqual)
        self.maxDiff = None

    def test_cef_notification(self):
        notifications = parse_notification_cef(raw_notifications, "test", get_unicode_string)

        template = Template("{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|"
                            "{{signature}}|{{name}}|{{severity}}|{{extension}}")

        results = []
        for notification in notifications:
            results.append(template.render(notification))
        self.assertEqual(results, cef_notifications)
        self.assertEqual(len(results), 3)

    def test_leef_notification(self):
        notifications = parse_notification_leef(raw_notifications, "test", get_unicode_string)
        self.assertEqual(notifications, leef_notifications)
        self.assertEqual(len(notifications), 15)

    def test_json_notification(self):
        notifications = parse_notification_json(raw_notifications, "test", get_unicode_string)
        self.assertEqual(notifications, json_notifications)
        self.assertEqual(len(notifications), 3)

    def test_cef_audit_logs(self):
        audits = parse_audit_log_cef(test_data_audit, "test", get_unicode_string)

        template = Template("{{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|"
                            "{{signature}}|{{name}}|{{severity}}|{{extension}}")

        results = []
        for audit in audits:
            results.append(template.render(audit))
        self.assertEqual(results, cef_output_audit)
        self.assertEqual(len(results), 5)

    def test_leef_audit_logs(self):
        audits = parse_audit_log_leef(test_data_audit, "test", get_unicode_string)
        self.assertEqual(audits, leef_output_audit)
        self.assertEqual(len(audits), 5)

    def test_json_audit_logs(self):
        audits = parse_audit_log_json(test_data_audit, "test", get_unicode_string)
        self.assertEqual(audits, json_output_audit)
        self.assertEqual(len(audits), 5)


if __name__ == '__main__':
    unittest.main()
