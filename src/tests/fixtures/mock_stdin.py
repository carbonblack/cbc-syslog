"""Mock stdin for setup wizard"""

import pathlib

CERTS_PATH = pathlib.Path(__file__).joinpath("../../fixtures/certs").resolve()
TMP_PATH = pathlib.Path(__file__).joinpath("../../fixtures/tmp").resolve()

TEMPLATE_HTTP = f"""{TMP_PATH}
template
http
https://server.company.com/endpoint
y
Authorization
Basic dXNlcjpwYXNzd29yZA==
n
y
y
y
y
n
y
Source1
defense-conferdeploy.net
orgkey
api_id
api_key
y
y
3
n
"""

TEMPLATE_TCP_TLS = f"""{TMP_PATH}
template
tcp+tls
0.0.0.0
8080
{CERTS_PATH.joinpath("rootCACert.pem")}
y
{CERTS_PATH.joinpath("rootCACert.pem")}
{CERTS_PATH.joinpath("rootCAKey.pem")}

y
n
n
y
n
n
Source1
defense-conferdeploy.net
orgkey
api_id
api_key
n
y
0
5
n
"""

TEMPLATE_UDP = f"""{TMP_PATH}
template
udp
0.0.0.0
8080
y
n
y
n
Source1
defense-conferdeploy.net
orgkey
api_id
api_key
n
y
8
y
Source2
defense-conferdeploy.net
orgkey2
api_id2
api_key2
n
y
3
n
"""

JSON_FILE = f"""{TMP_PATH}
json
file
{TMP_PATH}
Source1
defense-conferdeploy.net
orgkey
api_id
api_key
y
n
n
"""
