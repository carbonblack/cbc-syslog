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
import os
import pathlib
import sys

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
    """
    if not config.validate():
        log.error("Unable to validate config. Exiting cbc syslog")
        sys.exit(0)

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
        sys.exit(0)

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

    for source in config.sources():
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
            success = True

            with open(backup_file, "a") as backup:
                for alert in alerts:
                    if transforms["alerts"] == "json":
                        data = json.dumps(alert._info)
                    else:
                        data = transforms["alerts"].render(alert._info)

                    # Prevent repeating output if failure occurred
                    if success:
                        success = output.send(data)

                    if not success:
                        backup.write(data + "\n")

            # Clear Empty file
            if success and os.path.getsize(backup_file) == 0:
                os.remove(backup_file)

    # Save new state
    previous_state["end_time"] = end_time.strftime(TIME_FORMAT)

    with open(path, "w") as state_file:
        state_file.write(json.dumps(previous_state, indent=4))
