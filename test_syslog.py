#!/usr/bin/env python

from cb_defense_syslog import parse_cb_defense_response_cef
from test.test_data import test_data, expected_output
import unittest
from jinja2 import Template


class TestCbDefenseSyslogConnector(unittest.TestCase):
    def test_cef(self):
        responses = parse_cb_defense_response_cef(test_data, "test")

        template = Template(
            "{{source}}|{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        generated_output = "\n".join([template.render(log).encode('utf8') for log in responses])

        self.assertEqual(generated_output, expected_output)


if __name__ == '__main__':
    unittest.main()