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


def poll(config):
    """
    Poll Command

    Args:
        config (Config): Populated Config Object

    Returns:
        bool: Indicates short exit based on failure to execute
    """
    if not config.validate():
        log.error("Unable to validate config. Exiting cbc syslog")
        return False

    # Fetch previous state
    path = pathlib.Path(config.get("general.backup_dir")).joinpath(CBC_SYSLOG_STATE_FILE).resolve()
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
    SUPPORTED_INPUTS = ["alerts"]
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
    for filepath in pathlib.Path(config.get("general.backup_dir")).iterdir():
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

    for source in config.sources():
        if not source["alerts_enabled"]:
            continue

        cb = CarbonBlackCloud(source)
        # Attempt to catch up failed org
        failed_org = past_failed_orgs.get(source["org_key"], {})
        last_end_time = failed_org.get("alerts", None)

        # Use last_start_time if failed previously
        start_time = datetime.strptime(last_end_time, TIME_FORMAT) if last_end_time else new_start_time

        alerts = cb.fetch_alerts(start_time, end_time)

        # Check for failure and save start_time if failed
        if alerts is None:
            failed_org["alerts"] = start_time.strftime(TIME_FORMAT)
            if source["org_key"] not in past_failed_orgs:
                past_failed_orgs[source["org_key"]] = failed_org
        else:
            # Clear last_end_time on success
            if last_end_time:
                del failed_org["alerts"]
                if not failed_org:
                    del past_failed_orgs[source["org_key"]]

            backup_filename = f"cbc-{start_time.strftime(TIME_FORMAT)}.bck"
            backup_file = pathlib.Path(config.get("general.backup_dir")).joinpath(backup_filename).resolve()

            with open(backup_file, "a") as backup:
                for alert in alerts:
                    if transforms["alerts"] == "json":
                        data = json.dumps(alert._info)
                    else:
                        data = transforms["alerts"].render(alert._info)

                    # Prevent repeating output if failure occurred
                    if output_success:
                        output_success = output.send(data)

                    if not output_success:
                        backup.write(data + "\n")

            # Clear Empty file
            if output_success and backup_file.stat().st_size == 0:
                backup_file.unlink()

    # Save new state
    previous_state["end_time"] = end_time.strftime(TIME_FORMAT)

    with open(path, "w") as state_file:
        state_file.write(json.dumps(previous_state, indent=4))

    return True
