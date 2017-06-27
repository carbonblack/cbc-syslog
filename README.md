# Cb Defense Syslog TLS Connector

## Installation

1. Download latest release from:

    ```
    https://github.com/carbonblack/cb-defense-syslog-tls/releases
    ```

2. Install the rpm:

    ```
    rpm -ivh python-cb-defense-syslog-1.2-3.x86_64.rpm
    ```

3. Copy the example config file:

    ```
    cd /etc/cb/integrations/cb-defense-syslog

    cp cb-defense-syslog.conf.example cb-defense-syslog.conf
    ```

4. Modify the config file as needed

5. Test the new connector. As root, execute:

    ```
    /usr/share/cb/integrations/cb-defense-syslog/cb-defense-syslog --config-file /etc/cb/integrations/cb-defense-syslog/cb-defense-syslog.conf --log-file /var/log/cb/integrations/cb-defense-syslog/cb-defense-syslog.log
    ```
    
    Then:
    
    ```
    cat /var/log/cb/integrations/cb-defense-syslog/cb-defense-syslog.log
    ```
 
    A successful run will look like:
   
    ```
    2017-06-27 09:24:10,747 - __main__ - INFO - Found 1 Cb Defense Servers in config file
    2017-06-27 09:24:10,748 - __main__ - INFO - Handling notifications for https://api-eap01.conferdeploy.net
    2017-06-27 09:24:10,748 - __main__ - INFO - Attempting to connect to url: https://api-eap01.conferdeploy.net
    2017-06-27 09:24:10,748 - __main__ - INFO - connectorID = XXXX
    2017-06-27 09:24:10,845 - __main__ - INFO - <Response [200]>
    2017-06-27 09:24:10,845 - __main__ - INFO - sessionId = XXXX
    2017-06-27 09:24:10,888 - __main__ - INFO - <Response [200]>
    2017-06-27 09:24:10,889 - __main__ - INFO - successfully connected, no alerts at this time
    2017-06-27 09:24:10,889 - __main__ - INFO - There are no messages to forward to host
    ```
    
6. Uncomment the Cb Defense Connector (remove the beginning `#` from the last line) in `/etc/cron.d/cb-defense-syslog`

## Debug Logs

Debug Logs are stored in /var/log/cb/integrations/cb-defense-syslog/

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
# Configure the specific output.
# Valid options are: 'udp', 'tcp', 'tcp+tls'
#
#  udp     - Have the events sent over a UDP socket
#  tcp     - Have the events sent over a TCP socket
#  tcp+tls - Have the events sent over a TLS+TCP socket
#
output_type=tcp

#
# tcpout=IP:port - ie 1.2.3.5:8080
#
tcp_out=

#
# udpout=IP:port - ie 1.2.3.5:8080
#
udp_out=

[tls]

#
# Specify a file containing PEM-encoded CA certificates for verifying the peer server when using TLS+TCP syslog
#
#ca_cert = /etc/cb/integrations/cb-defense/cert.pem

#
# Uncomment tls_verify and set to "false" in order to disable verification of the peer server certificate
#
#tls_verify = true

[cbdefense1]

#
# Cb Defense Connector ID
#
connector_id = F8KF111111

#
# Cb Defense API Key
#
api_key = WT9T3QDP4UGCK2NS96111111

#
# Cb Defense Server URL
# NOTE: this is not the url to the web ui, but to the url of sensor checkins
#
server_url = https://server.yourcompany.com

#
# For more than one Cb Defense Server, add another server using the following template including the stanza
#
#[cbdefenseserver2]
#connector_id = F8KF111111
#api_key = WT9T3QDP4UGCK2NS96111111
#server_url = https://server2.yourcompany.com

```
