# *******************************************************
# Copyright (c) VMware, Inc. 2020-2023. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""CBC Syslog Core Functions"""

import json
import logging
import pathlib

from datetime import datetime, timedelta
from cbc_syslog.util import CarbonBlackCloud, Transform, Output

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
    new_start_time_str = previous_state.get("end_time", (datetime.now() - timedelta(seconds=90)).strftime(TIME_FORMAT))
    new_start_time = datetime.strptime(new_start_time_str, TIME_FORMAT)

    # Should stay behind 30s to ensure backend data is available
    end_time = datetime.now() - timedelta(seconds=30)

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

                backup_filename = f"cbc-{start_time.strftime(TIME_FORMAT)}.bck"
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
