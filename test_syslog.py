#!/usr/bin/env python

from cb_defense_syslog import parse_cb_defense_response_cef, parse_cb_defense_response_leef,parse_cb_defense_response_json
from test.test_data import test_data, expected_output_cef,expected_output_leef,expected_output_leef_with_context,expected_output_json,expected_output_json_with_context,test_event_context
import unittest
from jinja2 import Template

def fake_event_context(e):
    #eventContextFunc = partial(gather_notification_context, server.get('server_url'), server.get('api_key'),
    #                           server.get('connector_id'), True)
    return test_event_context

class TestCbDefenseSyslogConnector(unittest.TestCase):
    def test_cef(self):
        responses = parse_cb_defense_response_cef(test_data, "test")

        template = Template(
            "{{source}}|{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}")

        generated_output = "\n".join([template.render(log).encode('utf8') for log in responses])

        self.assertEqual(generated_output, expected_output_cef)

    def test_cef_with_context(self):
        responses = parse_cb_defense_response_cef(test_data, "test",eventContextFunc=fake_event_context)

        template = Template(
            "{{source}}|{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}|{{events}}|")

        generated_output = "\n".join([template.render(log).encode('utf8') for log in responses])
        print(generated_output)
        self.assertEqual(generated_output, expected_output_cef)


    def test_json(self):
        generated_json_output = parse_cb_defense_response_json(test_data,"test")
        self.assertEqual(generated_json_output,expected_output_json)

    def test_json_with_context(self):
        generated_json_output = parse_cb_defense_response_json(test_data, "test",eventContextFunc=fake_event_context)
        self.assertEqual(generated_json_output, expected_output_json_with_context)

    def test_leef(self):
        responses = parse_cb_defense_response_leef(test_data,"test")
        self.assertEqual(responses,expected_output_leef)

    def test_leef_with_context(self):
        responses = parse_cb_defense_response_leef(test_data, "test",eventContextFunc=fake_event_context)
        self.assertEqual(responses, expected_output_leef_with_context)

if __name__ == '__main__':
    unittest.main()
