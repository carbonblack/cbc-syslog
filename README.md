# Cb Defense Syslog TLS Connector

## Installation

1. Download latest release from:

    ```
    https://github.com/carbonblack/cb-defense-syslog-tls/releases
    ```

2. Install the rpm:

    ```
    rpm -ivh python-cb-yara-manager-1.0-1.x86_64.rpm
    ```

3. Copy the example config file:

    ```
    cd /etc/cb/integrations/cb-defense

    cp cb-defense-connector.conf.example cb-defense-connector.conf
    ```

4. Modify the config file as needed

5. Uncomment the Cb Defense Connector line from /etc/cron.d/cb-defense-connector

## Debug Logs

Debug Logs are stored in /var/log/cb/cb-defense.log

## Sample Config File

```
[general]

#
# Template for syslog output.
# This is a jinja 2 template
# NOTE: The source variable corresponds to the Cb Defense Server used to retrieve results
#
template = {{source}}|{{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}

#
# Specify a file containing PEM-encoded CA certificates for verifying the peer server when using TLS+TCP syslog
#
ca_cert = /etc/cb/integrations/cb-defense/cert.pem

#
# Specify a host to send notifications from all Cb Defense Servers
#
tcp_tls_host = localhost

#
# Specify the port to send notifications
#
tcp_tls_port = 8888

[cbdefenseserver1]

#
# Cb Defense Connector ID
#
connector_id = F8KFGNF100

#
# Cb Defense API Key
#
api_key = WT9T3QDP4UGCK2NS96999999

#
# Cb Defense Server URL
# NOTE: this is not the url to the web ui, but to the url of sensor checkins
#
server_url = https://server.yourcompany.com

#
# For more than one Cb Defense Servers, add another server using the following template including the stanza
#
#[cbdefenseserver2]
#connector_id = F8KFGNFVS6
#api_key = WT9T3QDP4UGCK2NS96JSGTDZ
#server_url = https://server.yourcompany.com
```