# Cb Defense Syslog TLS Connector

This connector allows you to forward alert notifications from your Cb Defense cloud instance into local, on-premise
SIEM systems that accept industry standard syslog notifications. By default, it will generate pipe-delimited syslog
messages containing the key metadata associated with any alert identified by the Cb Defense streaming prevention
system.

The syslog connector will aggregate data from one or more Cb Defense organizations into a single syslog stream.
The connector can be configured to use UDP, TCP, or encrypted (TCP over TLS) syslog protocols.

This connector is distributed as a binary RPM package compatible with any Red Hat or CentOS Linux distribution,
CentOS/RHEL 6.x and above, running on a 64-bit Intel platform.

## Installation

1. Install the software. As root on your Carbon Black or other RPM based 64-bit Linux distribution server:

    ```
    cd /etc/yum.repos.d
    ```
    ```
    curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
    ```
    ```
    yum install python-cb-defense-syslog
    ```

2. Copy the example config file:

    ```
    cd /etc/cb/integrations/cb-defense-syslog
    ```
    ```
    cp cb-defense-syslog.conf.example cb-defense-syslog.conf
    ```

3. Modify the config file `/etc/cb/integrations/cb-defense-syslog/cb-defense-syslog.conf` as needed

4. Test the new connector. As root, execute:

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

5. Start the connector by enabling it in `cron`. Uncomment the Cb Defense Connector (remove the beginning `#` from the last line) in `/etc/cron.d/cb-defense-syslog`.
   By default, the connector will run once per hour.

## Installation (via Docker)

You may wish to use a docker image of this software, rather than installing an RPM (which requires a
RedHat/CentOS/Fedora Linux distribution to run on).

At the time of writing, there is no _official_ image on [dockerhub](https://hub.docker.com/u/carbonblack), so for now, you'll need to build one
yourself.  Once built, you can either run this on the same system the docker image was built, or upload your newly-built image to dockerhub/a repo of your own.

1. Firstly, to build the image, do this:

    ```
    docker build . -t *your-docker-image-tag*
    ```

    If you _are_ hosting this yourself, ``your-docker-image-tag`` would typically include the
    _repo-name_/_username_/_project-name_:_tags_ you wish to use.

 > **Note**: You may leave off ``-t`` params, if you don't plan on publishing the image and thus don't need to tag the image (however you'll then need the *hash* of the newly-built image's to reference it later, last line of a successful build output, or from relevant line of ``docker images`` output).

2.  You can then run this container manually, by doing:
    ```
    docker run --name cb-defense-syslog -v /path/to/your/config/dir:/etc/cb/integrations/cb-defense-syslog *your-docker-image-tag-or-hash*
    ```
    With the above, you'll have the directory with _your_ config file within the container (see the
    sample at the end of this README for what to base yours on), expecting to be named appropriately
    (expected name is ``cb-defense-syslog.conf``).

> **Note**: since the config file contains sensitive credentials (the API key), you should protect it by setting appropriate ownership/permissions on the config file outside of docker, so only the user running docker can read this file.

The container ran will be named ``cb-defense-syslog``, you can then re-invoke it using this name.

You can then have this (containerized) software ran from ``crond`` (per **step-5** of the first _Installation_ section above) using instead either:

```
0 * * * * your-username docker run --rm --name cb-defense-syslog -v /path-to-your-config:/etc/cb/integrations/cb-defense-syslog <your-docker-image-tag>
```
or, if you ran the above step-2 command at least once:
```
0 * * * * your-username docker start cb-defense-syslog
```

..where ``your-username`` would be one that [has access to run the docker-client](https://docs.docker.com/install/linux/linux-postinstall/#manage-docker-as-a-non-root-user).  This can be tested
with ```docker info``` as that user.

The difference between the two is that the first variation will run a **new** container _on-the-hour_ each time,
and will also automatically remove that container after each run (since you can't start a new container with an
existing name).  This however also means it's *not* ideal for debugging, since the way it's configured, its log file
is sent only to stdout, and won't be available (since the container is removed after it runs).

> However if you do want the log file to instead persist outside the container (contrary to [best practices](https://12factor.net/logs)),
  you can simply change [the parameter to  ``--log-file``](./Dockerfile#L37).  You'll then also want to add another ``-v`` mount
  point parameter to docker run, where you want the log file to persist external to the container.

The second variation better allows for log-monitoring, since it simply re-starts the container
you previously ran (and thus named in **step-2** above), and all previous runs of the container 
are preserved, and available from the output of ``docker logs cb-defense-syslog``.

## Debug Logs

Debug Logs are stored in `/var/log/cb/integrations/cb-defense-syslog/`

## Sample Config File

    [general]

    #
    # Template for syslog output.
    # This is a jinja 2 template
    # NOTE: The source variable corresponds to the Cb Defense Server used to retrieve results
    #
    template = {{source}} {{version}}|{{vendor}}|{{product}}|{{dev_version}}|{{signature}}|{{name}}|{{severity}}|{{extension}}
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
    # udpout=IP:port - ie 1.2.3.5:8080
    #
    udp_out=

    #
    # httpout=http/https endpoint - ie https://server.company.com/endpoint
    # http_headers= {'key1': 'value1', 'key2': 'value2'} - ie {'content-type': 'application/json'}
    #
    http_out=
    http_headers=

    [tls]

    #
    # Specify a file containing PEM-encoded CA certificates for verifying the peer server when using TLS+TCP syslog
    #
    #ca_cert = /etc/cb/integrations/cb-defense/cert.pem

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
    #siem_connector_id = 
    siem_api_key = 
    #server_url = https://server2.yourcompany.com
