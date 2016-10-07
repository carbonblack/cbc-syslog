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