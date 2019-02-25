#!/usr/bin/env python

from cb_defense_syslog import parse_cb_defense_response_cef, parse_cb_defense_response_leef,parse_cb_defense_response_json
from test.test_data import test_data, expected_output_cef,expected_output_leef,expected_output_json
import unittest
from jinja2 import Template


class TestCbDefenseSyslogConnector(unittest.TestCase):
    def test_cef(self):
        responses = parse_cb_defense_response_cef(test_data, "test")

        template = Template(
            "{{source}}|{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        generated_output = "\n".join([template.render(log).encode('utf8') for log in responses])

        self.assertEqual(generated_output, expected_output_cef)

    def test_json(self):
        generated_json_output = parse_cb_defense_response_json(test_data,"test")
        self.assertEqual(generated_json_output,expected_output_json)

    def test_leef(self):
        responses = parse_cb_defense_response_leef(test_data,"test")
        self.assertEqual(responses,expected_output_leef)



if __name__ == '__main__':
    unittest.main()
