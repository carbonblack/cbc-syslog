# *******************************************************
# Copyright (c) Broadcom, Inc. 2020-2024. All Rights Reserved. Carbon Black.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""CBC Syslog Core Functions"""

import base64
import json
import logging
import pathlib

from configparser import ConfigParser, NoSectionError
from datetime import datetime, timedelta, timezone
from cbc_syslog.util import CarbonBlackCloud, Transform, Output
from cbc_syslog.util.example import (EXAMPLE_ALERT_CEF_TEMPLATE,
                                     EXAMPLE_ALERT_LEEF_TEMPLATE,
                                     EXAMPLE_AUDIT_CEF_TEMPLATE,
                                     EXAMPLE_AUDIT_LEEF_TEMPLATE,
                                     EXAMPLE_ALERT_TEMPLATE,
                                     EXAMPLE_AUDIT_TEMPLATE)

log = logging.getLogger(__name__)

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

CBC_SYSLOG_STATE_FILE = "cbc_syslog_state.json"

AUDIT_LOG_BATCHES = 10


def poll(config):
    """
    Poll Command

    Args:
        config (Config): Populated Config Object

    Returns:
        bool: Indicates short exit based on failure to execute
    """
    if not config.validate():
        log.error("Unable to validate config")
        return False

    # Fetch previous state
    backup_dir = pathlib.Path(config.get("general.backup_dir"))
    path = backup_dir.joinpath(CBC_SYSLOG_STATE_FILE).resolve()
    try:
        with open(path, "r") as state_file:
            previous_state = json.load(state_file)
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        log.warning(f"Previous state file ({CBC_SYSLOG_STATE_FILE}) not found or corrupted. "
                    f"Creating fresh state file using previous poll time 90s from current time")
        previous_state = {}

    # Use last end_time unless no state is available use 90s ago
    new_start_time_str = previous_state.get("end_time", (datetime.now(timezone.utc) - timedelta(seconds=90)).strftime(TIME_FORMAT))
    new_start_time = datetime.strptime(new_start_time_str, TIME_FORMAT)
    new_start_time = new_start_time.replace(tzinfo=timezone.utc)

    # Should stay behind 30s to ensure backend data is available
    end_time = datetime.now(timezone.utc) - timedelta(seconds=30)

    if end_time < new_start_time:
        log.error("Unable to fetch data please wait a minimum of 60s before next poll")
        return False

    past_failed_orgs = previous_state.setdefault("failed_orgs", {})

    # Create Supported Input Transforms
    SUPPORTED_INPUTS = ["alerts", "audit_logs"]
    transforms = {}
    for input in SUPPORTED_INPUTS:
        transform_config = config.transform(input)
        if transform_config["format"] == "json":
            transforms[input] = "json"
        else:
            transforms[input] = Transform(**transform_config)

    output = Output(**config.output())

    # Check backup directory for previously failed message and try to resend
    output_success = True
    try:
        for filepath in backup_dir.iterdir():
            filename = filepath.name
            if filename.startswith("cbc-") and filename.endswith(".bck"):
                count = 0
                with open(filepath, "r") as backup_file:
                    lines = backup_file.readlines()
                    for line in lines:
                        output_success = output.send(line)
                        if output_success:
                            count += 1
                        else:
                            break

                if output_success:
                    log.info(f"Successfully sent {count} messages from {filename}")
                    filepath.unlink()
                else:
                    # If failed to output abort backup retry
                    break
    except FileNotFoundError:
        log.error(f"Backup directory {backup_dir} is not a valid directory")
        return False

    for source in config.sources():
        for input in SUPPORTED_INPUTS:
            if not source[input + "_enabled"]:
                continue

            cb = CarbonBlackCloud(source)
            # Attempt to catch up failed org
            failed_org = past_failed_orgs.get(source["org_key"], {})
            last_end_time = failed_org.get(input, None)

            # Use last_start_time if failed previously
            start_time = datetime.strptime(last_end_time, TIME_FORMAT) if last_end_time else new_start_time

            data = None
            if input == "alerts":
                data = cb.fetch_alerts(start_time, end_time)
            elif input == "audit_logs":
                data = cb.fetch_audit_logs(AUDIT_LOG_BATCHES)

            # Check for failure and save start_time if failed
            if data is None:
                failed_org[input] = start_time.strftime(TIME_FORMAT)
                if source["org_key"] not in past_failed_orgs:
                    past_failed_orgs[source["org_key"]] = failed_org
            else:
                # Clear last_end_time on success
                if last_end_time:
                    del failed_org[input]
                    if not failed_org:
                        del past_failed_orgs[source["org_key"]]

                encoded = base64.b64encode(start_time.strftime(TIME_FORMAT).encode("ascii"))
                backup_filename = f"cbc-{encoded.decode('ascii')}.bck"
                backup_file = pathlib.Path(config.get("general.backup_dir")).joinpath(backup_filename).resolve()

                log.info(f"Sending {len(data)} {input} for {source.get('org_key')}")
                with open(backup_file, "a") as backup:
                    for item in data:
                        if transforms[input] == "json":
                            data_str = json.dumps(item if isinstance(item, dict) else item._info)
                        else:
                            data_str = transforms[input].render(item if isinstance(item, dict) else item._info)

                        # Prevent repeating output if failure occurred
                        if output_success:
                            output_success = output.send(data_str)

                        if not output_success:
                            backup.write(data_str + "\n")

                # Clear Empty file
                if output_success and backup_file.stat().st_size == 0:
                    backup_file.unlink()
                else:
                    log.warning(f"Failed to send data writing to backup file {backup_file.name}")

    # Save new state
    previous_state["end_time"] = end_time.strftime(TIME_FORMAT)

    with open(path, "w") as state_file:
        state_file.write(json.dumps(previous_state, indent=4))

    return True


def check(config, force=False):
    """
    Check API keys for enabled data and validate config

    Args:
        config (Config): Populated Config Object
        force (bool): Whether to test impacting data sources e.g. Audit Logs queue

    Returns
        bool: Whether the config is valid and API keys have necessary permissions
    """
    if not config.validate():
        log.error("Unable to validate config")
        return False

    success = True
    for source in config.sources():
        cb = CarbonBlackCloud(source)
        if not cb.test_key(force):
            success = False

    return success


def history(config, start, end, org_key=None):
    """
    History Command

    Args:
        config (Config): Populated Config Object
        start (str): ISO8601 Datetime string
        end (str): ISO8601 Datetime string
        org_key (str): Optional a singular org to fetch otherwise all sources fetched

    Returns:
        bool: Indicates short exit based on failure to execute
    """
    if not config.validate():
        log.error("Unable to validate config")
        return False

    start_time = datetime.strptime(start, TIME_FORMAT)
    end_time = datetime.strptime(end, TIME_FORMAT)

    if end_time < start_time:
        log.error("Unable to fetch history as end is before start")
        return False

    # Create Supported Input Transforms
    SUPPORTED_HISTORY_INPUTS = ["alerts"]
    transforms = {}
    for input in SUPPORTED_HISTORY_INPUTS:
        transform_config = config.transform(input)
        if transform_config["format"] == "json":
            transforms[input] = "json"
        else:
            transforms[input] = Transform(**transform_config)

    success = True

    output = Output(**config.output())
    output_success = True

    for source in config.sources():
        # If org_key specified skip until source matches org_key
        if org_key and source.get("org_key") != org_key:
            continue

        for input in SUPPORTED_HISTORY_INPUTS:
            if not source[input + "_enabled"]:
                continue

            cb = CarbonBlackCloud(source)

            data = None
            if input == "alerts":
                data = cb.fetch_alerts(start_time, end_time)

            # Check for failure
            if data is None:
                success = False
                continue

            log.info(f"Sending {len(data)} {input} for {source.get('org_key')}")
            for item in data:
                if transforms[input] == "json":
                    data_str = json.dumps(item if isinstance(item, dict) else item._info)
                else:
                    data_str = transforms[input].render(item if isinstance(item, dict) else item._info)

                # Prevent repeating output if failure occurred
                if output_success:
                    output_success = output.send(data_str)

                if not output_success:
                    log.error(f"Unable to send history for {source.get('org_key')} from start: {start_time} to end: {end_time}")
                    break

    return success and output_success


def valid_input(prompt, func, error_message=None):
    """
    Verify input and re-request if invalid.

    Args:
        prompt (str): The prompt to request input
        func (lambda): The function to validate the response
        error_message (str): The message to return in the case of failure
    """
    response = input(prompt)
    try:
        valid = func(response)
    except:
        valid = False

    if not valid:
        if error_message:
            print(error_message + "\n")
        else:
            print("Invalid Input\n")
        response = valid_input(prompt, func, error_message)

    return response


def wizard(output_file_path):
    """
    Setup Wizard Command

    Args:
        output_file_path (str): Output destination

    Returns:
        bool: Indicates short exit based on failure to execute
    """
    with pathlib.Path(output_file_path).open("w+") as output_file:

        output_file.write("[general]\n")
        backup_dir = valid_input("Provide an absolute path to an existing backup directory: ",
                                 lambda resp: pathlib.Path(resp).exists(),
                                 "Directory not found")
        backup_dir = backup_dir.replace("\\", "\\\\")
        output_file.write(f"backup_dir = \"{backup_dir}\"\n")

        output_format = valid_input("What format would you like the data to be sent (json / template): ",
                                    lambda resp: resp.lower() in ["json", "template"]).lower()
        output_file.write(f"output_format = \"{output_format}\"\n")

        output_type = valid_input("How would you like to data to be sent (udp / tcp / tcp+tls / http / file): ",
                                  lambda resp: resp.lower() in ["udp", "tcp", "tcp+tls", "http", "file"]).lower()
        output_file.write(f"output_type = \"{output_type}\"\n")

        if output_type == "file":
            file_path = valid_input("Provide an absolute path to where you want the files to be output: ",
                                    lambda resp: pathlib.Path(resp).exists(),
                                    "Directory not found")
            file_path = file_path.replace("\\", "\\\\")
            output_file.write(f"file_path = \"{file_path}\"\n")

        elif output_type == "http":
            http_out = input("Provide an http/https endpoint e.g.(https://server.company.com/endpoint): ")
            output_file.write(f"http_out = \"{http_out}\"\n")

            headers = {}
            while (input("Would you like to include a header (y or n): ").lower() == "y"):
                http_header_key = input("Provide header key: ")
                http_header_value = input("Provide header value: ")
                headers[http_header_key] = http_header_value

            if headers:
                output_file.write(f"http_headers = {json.dumps(json.dumps(headers))}\n")

            https_ssl_verify = input("Would you like to enable ssl verification (y or n): ").lower() == "y"
            output_file.write(f"https_ssl_verify = {'true' if https_ssl_verify else 'false'}\n")
        elif "tcp" in output_type:
            host = input("Provide the destination ip address: ")
            port = input("Provide the destination port: ")
            output_file.write(f"tcp_out = \"{host}:{port}\"\n")

            if "tls" in output_type:
                ca_cert = valid_input("Provide an absolute path to the ca cert: ",
                                      lambda resp: pathlib.Path(resp).exists(),
                                      "File not found")
                ca_cert = ca_cert.replace("\\", "\\\\")
                output_file.write(f"ca_cert = \"{ca_cert}\"\n")

                tls_verify = input("Would you like to enable tls verification (y or n): ").lower() == "y"
                output_file.write(f"tls_verify = {'true' if tls_verify else 'false'}\n")

                if tls_verify:
                    cert = valid_input("Provide an absolute path to the cert: ",
                                       lambda resp: pathlib.Path(resp).exists(),
                                       "File not found")
                    cert = cert.replace("\\", "\\\\")
                    output_file.write(f"cert = \"{cert}\"\n")

                    key = valid_input("Provide an absolute path to the key: ",
                                      lambda resp: pathlib.Path(resp).exists(),
                                      "File not found")
                    key = key.replace("\\", "\\\\")
                    output_file.write(f"key = \"{key}\"\n")

                    key_password = input("Provide key password if set otherwise leave empty: ")
                    output_file.write(f"key_password = \"{key_password}\"\n")

        elif output_type == "udp":
            host = input("Provide the destination ip address: ")
            port = input("Provide the destination port: ")
            output_file.write(f"udp_out = \"{host}:{port}\"\n")

        if output_format == "template":
            if input("Do you want to add an alert template (y or n): ").lower() == "y":
                if input("Do you want to use the example CEF template (y or n): ").lower() == "y":
                    output_file.write(EXAMPLE_ALERT_CEF_TEMPLATE)
                elif input("Do you want to use the example LEEF template (y or n): ").lower() == "y":
                    print("If you are using QRadar checkout out our native app instead "
                          "https://developer.carbonblack.com/reference/carbon-black-cloud/integrations/qradar-app\n")
                    output_file.write(EXAMPLE_ALERT_LEEF_TEMPLATE)
                else:
                    print("Template properties added. For more information on templates check out "
                          "https://github.com/carbonblack/cbc-syslog/tree/main#creating-a-custom-message-with-templates\n")
                    output_file.write(EXAMPLE_ALERT_TEMPLATE)

            if input("Do you want to add an audit log template (y or n): ").lower() == "y":
                if input("Do you want to use the example CEF template (y or n): ").lower() == "y":
                    output_file.write(EXAMPLE_AUDIT_CEF_TEMPLATE)
                elif input("Do you want to use the example LEEF template (y or n): ").lower() == "y":
                    print("If you are using QRadar checkout out our native app instead "
                          "https://developer.carbonblack.com/reference/carbon-black-cloud/integrations/qradar-app\n")
                    output_file.write(EXAMPLE_AUDIT_LEEF_TEMPLATE)
                else:
                    print("Template properties added. For more information on templates check out "
                          "https://github.com/carbonblack/cbc-syslog/tree/main#creating-a-custom-message-with-templates\n")
                    output_file.write(EXAMPLE_AUDIT_TEMPLATE)

        while True:
            output_file.write("\n")
            source_name = input("Provide a source name (letters and numbers only): ").replace(" ", "")
            output_file.write(f"[{source_name}]\n")

            server_url = input("Provide the HOSTNAME for the Carbon Black Cloud instance: ")
            output_file.write(f"server_url = \"{server_url}\"\n")

            org_key = input("Provide the ORG KEY for the Carbon Black Cloud organization: ")
            output_file.write(f"org_key = \"{org_key}\"\n")

            custom_api_id = input("Provide the ID for the custom API key: ")
            output_file.write(f"custom_api_id = \"{custom_api_id}\"\n")

            custom_api_key = input("Provide the KEY for the custom API key: ")
            output_file.write(f"custom_api_key = \"{custom_api_key}\"\n")

            audit_logs_enabled = input("Do you want to enable Audit Logs (y or n): ").lower() == "y"
            output_file.write(f"audit_logs_enabled = {'true' if audit_logs_enabled else 'false'}\n")

            alerts_enabled = input("Do you want to enable Alerts (y or n): ").lower() == "y"
            output_file.write(f"alerts_enabled = {'true' if alerts_enabled else 'false'}\n")

            if alerts_enabled:
                output_file.write(f"\n[[{source_name}.alert_rules]]\n")

                minimum_severity = valid_input("Provide a minimum severity between 1 and 10: ",
                                               lambda x: int(x) > 0 and int(x) <= 10)
                output_file.write(f"minimum_severity = {minimum_severity}\n")

                print("If you want to provide more rules or add additional filters check out the README for more information\n")

            if input("Do you want to add a proxy (y or n): ").lower() == "y":
                proxy_url = input("Provide the URL for the Proxy Server: ")
                output_file.write(f"proxy = \"{proxy_url}\"\n")

            if input("Do you want to add another organization (y or n): ").lower() == "n":
                break
    print(f"\nTo test your configuration use:\n"
          f"cbc_syslog_forwarder --log-file /some/path/cbc-syslog.log check {output_file_path}\n\n"
          f"To run the syslog forwarder use:\n"
          f"cbc_syslog_forwarder --log-file /some/path/cbc-syslog.log poll {output_file_path}")


def convert(config_file_path, output_file_path):
    """
    Convert Command

    Args:
        config_file_path (str): v1 Config file ini path
        output_file_path (str): Output destination

    Returns:
        bool: Indicates short exit based on failure to execute
    """
    v1config = ConfigParser()
    v1config.read_file(open(config_file_path))

    with pathlib.Path(output_file_path).open("w+") as output_file:

        output_file.write("[general]\n")

        backup_dir = v1config.get("general", "back_up_dir")
        backup_dir = backup_dir.replace("\\", "\\\\")
        output_file.write(f"backup_dir = \"{backup_dir}\"\n")

        output_format = v1config.get("general", "output_format").lower()
        if output_format == "cef" or output_format == "leef":
            output_format = "template"
        output_file.write(f"output_format = \"{output_format}\"\n")

        output_type = v1config.get("general", "output_type").lower()
        output_file.write(f"output_type = \"{output_type}\"\n")

        if output_type == "http":
            http_out = v1config.get("general", "http_out")
            output_file.write(f"http_out = \"{http_out}\"\n")

            http_headers = v1config.get("general", "http_headers")
            output_file.write(f"http_headers = \"{http_headers}\"\n")

            https_ssl_verify = v1config.get("general", "https_ssl_verify").lower()
            output_file.write(f"https_ssl_verify = {https_ssl_verify}\n")
        elif "tcp" in output_type:
            tcp_out = v1config.get("general", "tcp_out")
            output_file.write(f"tcp_out = \"{tcp_out}\"\n")

            try:
                if "tls" in output_type:
                    ca_cert = v1config.get("tls", "ca_cert")
                    ca_cert = ca_cert.replace("\\", "\\\\")
                    output_file.write(f"ca_cert = \"{ca_cert}\"\n")

                    tls_verify = v1config.get("tls", "tls_verify").lower()
                    output_file.write(f"tls_verify = {tls_verify}\n")

                    if tls_verify == 'true':
                        cert = v1config.get("tls", "cert")
                        cert = cert.replace("\\", "\\\\")
                        output_file.write(f"cert = \"{cert}\"\n")

                        key = v1config.get("tls", "key")
                        key = key.replace("\\", "\\\\")
                        output_file.write(f"key = \"{key}\"\n")

                        key_password = v1config.get("tls", "key_password")
                        output_file.write(f"key_password = \"{key_password}\"\n")
            except NoSectionError:
                print("Unable to find section [tls]. Aborting")
                return False

        elif output_type == "udp":
            udp_out = v1config.get("general", "udp_out")
            output_file.write(f"udp_out = \"{udp_out}\"\n")

        if output_format == "template":
            print("With the latest v7 Alerts data CEF and LEEF formats have been adjust to use templates for full customization")
            if input("Do you want to add an alert template (y or n): ").lower() == "y":
                if input("Do you want to use the example CEF template (y or n): ").lower() == "y":
                    output_file.write(EXAMPLE_ALERT_CEF_TEMPLATE)
                elif input("Do you want to use the example LEEF template (y or n): ").lower() == "y":
                    print("If you are using QRadar checkout out our native app instead "
                          "https://developer.carbonblack.com/reference/carbon-black-cloud/integrations/qradar-app\n")
                    output_file.write(EXAMPLE_ALERT_LEEF_TEMPLATE)
                else:
                    print("Template properties added. For more information on templates check out "
                          "https://github.com/carbonblack/cbc-syslog/tree/main#creating-a-custom-message-with-templates\n")
                    output_file.write(EXAMPLE_ALERT_TEMPLATE)

            if input("Do you want to add an audit log template (y or n): ").lower() == "y":
                if input("Do you want to use the example CEF template (y or n): ").lower() == "y":
                    output_file.write(EXAMPLE_AUDIT_CEF_TEMPLATE)
                elif input("Do you want to use the example LEEF template (y or n): ").lower() == "y":
                    print("If you are using QRadar checkout out our native app instead "
                          "https://developer.carbonblack.com/reference/carbon-black-cloud/integrations/qradar-app\n")
                    output_file.write(EXAMPLE_AUDIT_LEEF_TEMPLATE)
                else:
                    print("Template properties added. For more information on templates check out "
                          "https://github.com/carbonblack/cbc-syslog/tree/main#creating-a-custom-message-with-templates\n")
                    output_file.write(EXAMPLE_AUDIT_TEMPLATE)

        for section in v1config.sections():
            if section == 'general' or section == 'tls':
                continue
            output_file.write("\n")
            output_file.write(f"[{section}]\n")
            output_file.write(f"server_url = \"{v1config.get(section, 'server_url')}\"\n")
            print(f"Processing section ({section}) - NEW CUSTOM API key REQUIRED\n")
            print("Create a CUSTOM API key in the Carbon Black Cloud organization with the following permissions:\n"
                  "- org.alerts READ\n"
                  "- org.audits READ\n\n"
                  "For more information on creating a CUSTOM API key see the User Guide\n"
                  "https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/"
                  "GUID-F3816FB5-969F-4113-80FC-03981C65F969.html\n")
            org_key = input("Provide the ORG KEY for the Carbon Black Cloud organization: ")
            output_file.write(f"org_key = \"{org_key}\"\n")

            custom_api_id = input("Provide the ID for the custom API key: ")
            output_file.write(f"custom_api_id = \"{custom_api_id}\"\n")

            custom_api_key = input("Provide the KEY for the custom API key: ")
            output_file.write(f"custom_api_key = \"{custom_api_key}\"\n")

            audit_logs_enabled = input("Do you want to enable Audit Logs (y or n): ").lower() == "y"
            output_file.write(f"audit_logs_enabled = {'true' if audit_logs_enabled else 'false'}\n")

            alerts_enabled = input("Do you want to enable Alerts (y or n): ").lower() == "y"
            output_file.write(f"alerts_enabled = {'true' if alerts_enabled else 'false'}\n")

            if alerts_enabled:
                output_file.write(f"\n[[{section}.alert_rules]]\n")

                minimum_severity = valid_input("Provide a minimum severity between 1 and 10: ",
                                               lambda x: int(x) > 0 and int(x) <= 10)
                output_file.write(f"minimum_severity = {minimum_severity}\n")

                print("If you want to provide more rules or add additional filters check out the README for more information\n")

        print(f"\nTo test your configuration use:\n"
              f"cbc_syslog_forwarder --log-file /some/path/cbc-syslog.log check {output_file_path}\n\n"
              f"To run the syslog forwarder use:\n"
              f"cbc_syslog_forwarder --log-file /some/path/cbc-syslog.log poll {output_file_path}")
