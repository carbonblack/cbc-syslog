# Carbon Black Cloud Syslog Connector

This connector allows you to forward alert notifications and audit logs from your Carbon Black Cloud instance 
into local, on-premise systems that accept industry standard syslog notifications. By default, it will generate 
pipe-delimited syslog messages containing the key metadata associated with any alert identified by the Cb Defense 
streaming prevention system.

The syslog connector will aggregate data from one or more Carbon Black Cloud organizations into a single syslog stream.
The connector can be configured to use UDP, TCP, or encrypted (TCP over TLS) syslog protocols.

This connector is distributed as a pip package compatible with Python 2.7, running on a 64-bit Intel platform.

## System Requirments:

1. Python 2.7
2. pip 

## Installation (via PyPi/pip)

1. Please Navigate to the following URL to install the package: `https://pypi.org/project/cbc-syslog/` and follow the 
installation instructions.

## Installation (via GitHub)

1. Pull down the Repo. You may use `git clone` or pull down the zip file directly from GitHub.

2. Navigate to the following location within the package `/src/cbc_syslog`

3. Copy and paste the Configuration File example shown below into your own `.conf` file and modify it to your own 
specifications. Below is a table of all the configurable inputs that can be used in the syslog connector.

    | Input      | Required | Description |     
    | ----------- | ----------- | ----------- | 
    | template      | Y       | Template for syslog output.      |
    | back_up_dir      | Y       | Location of the Backup Directory. This will be the location of back up files in the event that results fail to send to Syslog      |
    | policy_action_severity      | Y       | This sets the default severity level for POLICY_ACTION notifications. By default it is 4.      |
    | output_format      | Y       | Output format of the data sent. Currently support json, leef, and cef formats      |
    | output_type      | Y       | Configures the specific output. Valid options are: 'udp', 'tcp', 'tcp+tls', 'http'      |
    | tcpout      | Y       | Output Type: IP:port      |
    | udp_out      | Y       | Output Type: IP:port      |
    | http_out      | Y       | Output Type: http/https endpoint - ie https://server.company.com/endpoint      |
    | http_headers      | Y       | Required if using http: {'key1': 'value1', 'key2': 'value2'}     |
    | https_ssl_verify      | Y       | Required if using http: True or False      |
    | requests_ca_cert      | N       | Override ca file for self signed certificates when using https      |
    | ca_cert      | N       | Specifies a file containing PEM-encoded CA certificates for verifying the peer server when using TLS+TCP syslog      |
    | cert      | N       | Specifies a file containing PEM-encoded client certificate for verifying this client when using TLS+TCP syslog      |
    | key      | N       | Specifies a file containing PEM-encoded private key for verifying this client when using TLS+TCP syslog      |
    | key_password      | N       | Specifies the password to decrypt the given private key when using TLS+TCP syslog      |
    | tls_verify      | N       |  True or False      |
    | api_connector_id      | Y       | API Connector ID      |
    | api_key      | Y       | API Key      |
    | siem_connector_id      | Y       | SIEM Connector ID      |
    | siem_api_key      | Y       |  SIEM Key      |
    | server_url      | Y       | Server URL      |

4.Create a `.txt` file for Logs.


5. Test the new connector:

    Verify that you are running Python 2.7:
    
    ```
    python --version 
    ```
   
   Then run the following command:

    ```
    python cb_defense_syslog.py -l [LOG_FILE_LOCATION] -c [CONFIG_FILE_LOCATION]
    ```

    A successful run will look like:

    ```
    INFO:__main__:CB Defense Syslog 1.0
    INFO:__main__:Number of files in store forward: 0
    INFO:__main__:Found 2 Cb Defense Servers in config file
    INFO:__main__:Handling notifications for https://defense-test03.cbdtest.io
    INFO:notifications:Attempting to connect to url: https://defense-test03.cbdtest.io
    INFO:notifications:<Response [200]>
    INFO:notifications:successfully connected, no alerts at this time
    INFO:__main__:Sending Notifications
    INFO:__main__:There are no messages to forward to host
    INFO:__main__:Done Sending Notifications
    INFO:__main__:Sending Audit Logs
    INFO:__main__:Sending 18 messages to 00.00.000.00:000
    INFO:__main__:Done Sending Audit Logs
    INFO:__main__:Handling notifications for https://defense-eap01.conferdeploy.net
    INFO:notifications:Attempting to connect to url: https://defense-eap01.conferdeploy.net
    INFO:notifications:<Response [200]>
    INFO:__main__:Sending Notifications
    INFO:__main__:Sending 3 messages to 00.00.000.00:000
    INFO:__main__:Done Sending Notifications
    INFO:__main__:Sending Audit Logs
    INFO:__main__:Sending 24 messages to 00.00.000.00:000
    INFO:__main__:Done Sending Audit Logs
    ```
    
## Sample Config File

    [general]
    
    #
    # Template for syslog output.
    # This is a jinja 2 template
    # NOTE: The source variable corresponds to the Cb Defense Server used to retrieve results
    #
    template = {{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}
    
    #
    #Location of the Backup Directory
    #This will be the location of back up files in the event that results fail to send to Syslog
    #
    
    back_up_dir = /Users/jdoe/Documents/
    
    #
    # This sets the default severity level for POLICY_ACTION notifications.  By default it is 4.
    #
    # 0 - Emergency: System is unusable.
    #
    # 1 - Alert: Action must be taken immediately.
    #
    # 2 - Critical: Critical conditions.
    #
    # 3 - Error: Error conditions.
    #
    # 4 - Warning: Warning conditions.
    #
    # 5 - Notice: Normal but significant condition.
    #
    # 6 - Informational: Informational messages.
    #
    # 7 - Debug: Debug-level messages.
    #
    policy_action_severity = 4
    
    
    #
    # Output format of the data sent. Currently support json or cef formats
    #
    # Warning: if using json output_format, we recommend NOT using UDP output_type
    #
    output_format=cef
    
    #
    # Configure the specific output.
    # Valid options are: 'udp', 'tcp', 'tcp+tls', 'http'
    #
    #  udp     - Have the events sent over a UDP socket
    #  tcp     - Have the events sent over a TCP socket
    #  tcp+tls - Have the events sent over a TLS+TCP socket
    #  http    - Have the events sent over a HTTP connection
    #
    output_type=tcp
    
    #
    # tcpout=IP:port - ie 1.2.3.5:514
    #
    tcp_out=
    
    #
    # udpout=IP:port - ie 1.2.3.5:514
    #
    udp_out=
    
    #
    # httpout=http/https endpoint - ie https://server.company.com/endpoint
    # http_headers= {'key1': 'value1', 'key2': 'value2'} - ie {'content-type': 'application/json'}
    # https_ssl_verify = True or False
    #
    http_out=
    http_headers= {'content-type': 'application/json'}
    https_ssl_verify=True
    
    #
    # Override ca file for self signed certificates when using https
    # This is typically a .pem file
    #
    #requests_ca_cert=/usr/share/cb/integrations/cb-defense-syslog/cert.pem
    
    [tls]
    
    #
    # Specify a file containing PEM-encoded CA certificates for verifying the peer server when using TLS+TCP syslog
    #
    #ca_cert = /etc/cb/integrations/cb-defense/ca.pem
    
    #
    # Optionally specify a file containing PEM-encoded client certificate for verifying this client when using TLS+TCP syslog
    # If cert is specified, key is a required parameter
    #
    #cert = /etc/cb/integrations/cb-defense/cert.pem
    
    #
    # Optionally specify a file containing PEM-encoded private key for verifying this client when using TLS+TCP syslog
    # If key is specified, cert is a required parameter
    #
    #key = /etc/cb/integrations/cb-defense/cert.key
    
    #
    # Optionally specify the password to decrypt the given private key when using TLS+TCP syslog
    #
    #key_password = p@ssw0rd1
    
    #
    # Uncomment tls_verify and set to "false" in order to disable verification of the peer server certificate
    #
    #tls_verify = true
    
    [cbdefense1]
    
    #
    # Cb Defense API Connector ID
    #
    api_connector_id = GO5M953111
    
    #
    # Cb Defense API Key
    #
    api_key = BYCRM7BRNSH0CXZR5V1Y3111
    
    #
    # Cb Defense SIEM Connector ID
    #
    siem_connector_id = UEUWR4U111
    
    #
    # Cb Defense SIEM Key
    #
    siem_api_key = XNS5UKWZXZMCC3CYC7DFM111
    
    #
    # Cb Defense Server URL
    # NOTE: this is not the url to the web ui, but to the API URL (for example, https://api-prod05.conferdeploy.net)
    #
    server_url = https://server1.yourcompany.com
    
    #
    # For more than one Cb Defense Server, add another server using the following template including the stanza
    #
    #[cbdefenseserver2]
    #api_connector_id = KJARWBZ111
    #api_key = CQF35EIH2WDF69PTWKGC4111
    #server_url = https://server2.yourcompany.com

