#!/usr/bin/env python
import logging.handlers
import unittest
import os

from cbc_syslog.util.config import parse_config, verify_config

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


class TestConfig(unittest.TestCase):

    def setUp(self):
        super(TestConfig, self).setUp()
        self.addTypeEqualityFunc(str, self.assertMultiLineEqual)
        self.addTypeEqualityFunc(dict, self.assertDictEqual)
        self.addTypeEqualityFunc(list, self.assertListEqual)
        self.addTypeEqualityFunc(tuple, self.assertTupleEqual)
        self.addTypeEqualityFunc(set, self.assertSetEqual)
        self.addTypeEqualityFunc(frozenset, self.assertSetEqual)
        self.maxDiff = None

    def test_cef_config(self):
        config = parse_config(os.path.dirname(__file__) + '/fixtures/cef.conf')
        output_params, server_list = verify_config(config)

        self.assertEqual(output_params['output_format'], 'cef')
        self.assertEqual(output_params['output_type'], 'udp')
        self.assertEqual(output_params['output_host'], '0.0.0.0')
        self.assertEqual(output_params['output_port'], 8886)

        self.assertEqual(len(server_list), 1)

    def test_leef_config(self):
        config = parse_config(os.path.dirname(__file__) + '/fixtures/leef.conf')
        output_params, server_list = verify_config(config)

        self.assertEqual(output_params['output_format'], 'leef')
        self.assertEqual(output_params['output_type'], 'tcp+tls')
        self.assertEqual(output_params['output_host'], '0.0.0.0')
        self.assertEqual(output_params['output_port'], 8888)

        self.assertEqual(output_params['ca_cert'], '/etc/cb/integrations/cbc-syslog/ca.pem')
        self.assertEqual(output_params['tls_cert'], '/etc/cb/integrations/cbc-syslog/cert.pem')
        self.assertEqual(output_params['tls_key'], '/etc/cb/integrations/cbc-syslog/cert.key')
        self.assertEqual(output_params['tls_verify'], True)

        self.assertEqual(len(server_list), 2)

    def test_json_config(self):
        config = parse_config(os.path.dirname(__file__) + '/fixtures/json.conf')
        output_params, server_list = verify_config(config)

        self.assertEqual(output_params['output_format'], 'json')
        self.assertEqual(output_params['output_type'], 'http')
        self.assertEqual(output_params['output_host'], 'http://0.0.0.0:5001/http_out')
        self.assertEqual(output_params['output_port'], None)
        self.assertEqual(output_params['http_headers'], {'content-type': 'application/json'})
        self.assertEqual(output_params['https_ssl_verify'], False)

        self.assertEqual(len(server_list), 1)


if __name__ == '__main__':
    unittest.main()
