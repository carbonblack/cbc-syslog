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
import sys

from datetime import datetime, timedelta
from cbc_syslog.util import CarbonBlackCloud, Transform, Output

log = logging.getLogger(__name__)

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
    path = pathlib.Path(config.get("backup_dir")).joinpath(CBC_SYSLOG_STATE_FILE).resolve()
    with open(path) as state_file:
        previous_state = json.load(state_file)

    # Use last end_time unless no state is available use 90s ago
    new_start_time = previous_state.get("end_time", datetime.now() - timedelta(seconds=90))
    # Should stay behind 30s to ensure backend data is available
    end_time = datetime.now() - timedelta(seconds=30)

    if end_time < new_start_time:
        log.error("Unable to fetch data please wait a minimum of 60s before next poll")
        sys.exit(0)

    past_failed_orgs = previous_state.get("failed_orgs", {})

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
        start_time = last_end_time if last_end_time else new_start_time

        alerts = cb.fetch_alerts(start_time, end_time)

        # Check for failure and save start_time if failed
        if alerts is None:
            failed_org["alerts"] = start_time
        else:
            del past_failed_orgs[source["org_key"]]

            backup_file = f"cbc-{start_time.isoformat()}.bck"
            with open(backup_file, "a") as backup:
                success = True
                for alert in alerts:
                    if transforms["alerts"] == "json":
                        data = str(alert)
                    else:
                        data = transforms["alerts"].render(alert)

                    # Prevent repeating output if failure occurred
                    if success:
                        success = output.send(data)

                    if not success:
                        backup.write(data + "\n")

    # Save new state
    previous_state["end_time"] = end_time

    with open(path) as state_file:
        state_file.write(json.dumps(previous_state, indent=4))
