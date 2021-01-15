# Carbon Black Cloud Syslog Connector

## Breaking Changes with v1.3.1

* Leef format logs have been rewritten to better utilize common variables and include as much information as possible
* `cb_defense_syslog.py` has been renamed to `cbc_syslog.py`
* Example config file and cacert have moved from the `cb-defense-syslog` folder to a `cbc-syslog` folder
* Example cron job file has been renamed to cbc-syslog and uses the new file and folder locations

## Introduction

The syslog connector lets administrators forward alert notifications and audit logs from their Carbon Black Cloud instance to local, on-premise systems, and:

* Generates pipe-delimited syslog messages with alert metadata identified by the streaming prevention system
* Aggregates data from one or more Carbon Black Cloud organizations into a single syslog stream
* Can be configured to use UDP, TCP, or encrypted (TCP over TLS) syslog protocols


### Helpful Links
* [Updating PATH in a Windows Environment](https://www.java.com/en/download/help/path.xml)

### Customer Support

Use the [Developer Community Forum](https://community.carbonblack.com/t5/user/userloginpage?redirectreason=permissiondenied&dest_url=https%3A%2F%2Fcommunity.carbonblack.com%2Ft5%2FDeveloper-Relations%2Fbd-p%2Fdeveloper-relations) to report bugs, request changes, and discuss with other API developers in the Carbon Black Community.

### Requirements

* CB Defense or CB ThreatHunter
* [Python 2.7 or Python 3 running on a 64-bit Intel platform](https://www.python.org/downloads/)
* [pip](https://pip.pypa.io/en/stable/installing/)
* [Jinja2](https://pypi.org/project/Jinja2/)
* [requests](https://pypi.org/project/requests/2.24.0/)
* [psutil](https://pypi.org/project/psutil/5.7.3/)

### Test Requirements

* [Flask](https://pypi.org/project/Flask/1.1.1/)
* [Pytest](https://pypi.org/project/pytest/6.0.1)

## Installation

You can install the Syslog Connector using either PyPI or GitHub.

### PyPI Installation

1. Run the following command in your terminal: `pip install cbc-syslog`

2. Navigate to the Python package location:

    Python {Version}
    MacOS: `/python{version}/site-packages/cbc_syslog`
    Windows: `C:\Python{version}\Lib\site-packages\cbc_syslog`
    Linux: `/usr/lib/python{version}/site-packages/cbc_syslog`

    Python 2.7
    MacOS: `/python2.7/site-packages/cbc_syslog`
    Windows: `C:\Python27\Lib\site-packages\cbc_syslog`
    Linux: `/usr/lib/python2.7/site-packages/cbc_syslog`

3. Copy and paste the Configuration File example shown below into your own `.conf` file and modify it to your own
specifications. Below is a table of all the configurable inputs that can be used in the syslog connector.

    | Input      | Required | Description |     
    | ----------- | ----------- | ----------- |
    | template      | Y       | Template for syslog output.      |
    | back_up_dir      | Y       | Location of the Backup Directory. This will be the location of backup files in the event that results fail to send to Syslog. The backup files are deleted upon a successful process.      |
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

4. Create a `.txt` file for Logs.
5. Create an empty backup folder. The location of this folder will be placed in back_up_dir seen in the
Configuration file.  For more information on the behavior of the backup folder please see the description of back_up_dir
in Step 3.
6. Test the new connector and run the following command:

    ```
    python cbc_syslog.py -l [LOG_FILE_LOCATION] -c [CONFIG_FILE_LOCATION]
    ```

    A successful run will look like:

    ```
    INFO:__main__:Carbon Black Cloud Syslog 2.0
    INFO:__main__:Number of files in store forward: 0
    INFO:__main__:Found 2 Carbon Black Cloud Servers in config file
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


**Note: If you're having trouble installing on Centos 7 follow these instructions**

* Verify python verison:
```
>$ python --version
Python 2.7.5
```

* Pip not found
```
>$ sudo yum install epel-release
>$ sudo yum -y install python-pip
```

* Python.h file not found with compile errors
```
>$ sudo yum install python-devel
>$ sudo pip install cbc-syslog
```

### GitHub Installation

1. Pull down the Repo. You may use `git clone` or pull down the zip file directly from GitHub.

2. Navigate to the following location within the package `/src/cbc_syslog`

3. Follow Steps 3-6 in the PyPI installation instructions.

### Using Docker
This assumes that docker is installed in your environments.  See https://www.docker.com/ for more information

1. Build the docker container:
```
sudo docker build -f docker/Dockerfile .
```
The last line will be "Successfully built <container Id>".  Take note of the container id to connect to it.

2. Run the container interactively:  
```
sudo docker container run -it <containerId> /bin/bash
```
3. Within the container, configure syslog as per Steps 3-6 in the PyPI installation instructions.

### Sample Config File

    [general]

    #
    # Template for syslog output.
    # This is a jinja 2 template
    # NOTE: The source variable corresponds to the Carbon Black Cloud Server used to retrieve results
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
    #requests_ca_cert=/usr/share/cb/integrations/cbc-syslog/cert.pem

    [tls]

    #
    # Specify a file containing PEM-encoded CA certificates for verifying the peer server when using TLS+TCP syslog
    #
    #ca_cert = /etc/cb/integrations/cbc-syslog/ca.pem

    #
    # Optionally specify a file containing PEM-encoded client certificate for verifying this client when using TLS+TCP syslog
    # If cert is specified, key is a required parameter
    #
    #cert = /etc/cb/integrations/cbc-syslog/cert.pem

    #
    # Optionally specify a file containing PEM-encoded private key for verifying this client when using TLS+TCP syslog
    # If key is specified, cert is a required parameter
    #
    #key = /etc/cb/integrations/cbc-syslog/cert.key

    #
    # Optionally specify the password to decrypt the given private key when using TLS+TCP syslog
    #
    #key_password = p@ssw0rd1

    #
    # Uncomment tls_verify and set to "false" in order to disable verification of the peer server certificate
    #
    #tls_verify = true

    [CarbonBlackCloudServer1]

    #
    # Carbon Black Cloud API Connector ID
    #
    api_connector_id = GO5M953111

    #
    # Carbon Black Cloud API Key
    #
    api_key = BYCRM7BRNSH0CXZR5V1Y3111

    #
    # Carbon Black Cloud SIEM Connector ID
    #
    siem_connector_id = UEUWR4U111

    #
    # Carbon Black Cloud SIEM Key
    #
    siem_api_key = XNS5UKWZXZMCC3CYC7DFM111

    #
    # Carbon Black Cloud Server URL
    # NOTE: this is not the url to the web ui, but to the API URL (for example, https://api-prod05.conferdeploy.net)
    #
    server_url = https://server1.yourcompany.com

    #
    # For more than one Carbon Black Cloud Server, add another server using the following template including the stanza
    #
    #[CarbonBlackCloudServer2]
    #api_connector_id = KJARWBZ111
    #api_key = CQF35EIH2WDF69PTWKGC4111
    #server_url = https://server2.yourcompany.com
