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

"""CBC Syslog Forwarder main script"""

import argparse
import json
import logging
import logging.handlers
import pathlib
import psutil
import sys

from datetime import datetime, timedelta
from cbc_syslog.util import Config, CarbonBlackCloud, Transform, Output

log = logging.getLogger(__name__)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

CBC_SYSLOG_STATE_FILE = "cbc_syslog_state.json"

# CLI interface

# Create core objects
#   Config
#   Carbon Black Cloud
#   Transform
#   Output

# Check backup directory for cbc-{IS08601 Timestamp}.bck
# Try to Read/Send backup files
# Get previous state/time from backup directory (cbc_syslog_state.json)
# Get new data from last_time to current time - 30s
# Transform data
# Output data and check for failed orgs
# Update state based on failed orgs


def main(args):
    """Core CBC Syslog Logic"""
    config = Config(args.config_file)

    if not config.validate():
        log.error("Unable to validate config. Exiting cbc syslog")
        sys.exit(0)

    cb = CarbonBlackCloud(config.sources())

    # Fetch previous state
    path = pathlib.Path(config.get("backup_dir")).joinpath(CBC_SYSLOG_STATE_FILE).resolve()
    with open(path) as state_file:
        previous_state = json.load(state_file)

    # Use last end_time unless no state is available use 90s ago
    start_time = previous_state.get("alerts", {}).get("end_time", datetime.now() - timedelta(seconds=90))
    # Should stay behind 30s to ensure backend data is available
    end_time = datetime.now() - timedelta(seconds=30)

    if end_time < start_time:
        log.error("Unable to fetch data please wait a minimum of 60s before next poll")
        sys.exit(0)

    alerts, failed_orgs = cb.fetch_alerts(start_time, end_time)

    alert_config = config.transform("alerts")
    transform_alerts = Transform(alert_config.header,
                                 alert_config.extension,
                                 alert_config.get("type_field"),
                                 alert_config.get("time_format"),
                                 alert_config.get("time_fields", []))
    output = Output(config.output())

    backup_file = f"cbc-{start_time.isoformat()}.bck"
    with open(backup_file, "a") as backup:
        success = True
        for alert in alerts:
            if alert_config["format"] == "json":
                data = str(alert)
            else:
                data = transform_alerts.render(alert)

            # Prevent repeating output if failure occurred
            if not success:
                success = output.send(data)
            else:
                backup.write(data + "\n")

    # Catch up failed orgs if they have succeeded and update current state
    # past_failed_orgs = previous_state.get("alerts", {}).get("failed_orgs", {})
    # for org in past_failed_orgs.keys():
    #     last_start_time = past_failed_orgs[org]


if __name__ == "__main__":

    """
         --log-file

        poll
            config-file
        history
            config-file
            source
            start
            end
        convert
            config-file
            --output
        setup
            --output
    """

    argparser = argparse.ArgumentParser()
    argparser.add_argument("--log-file", "-l", help="Log file location", default="stdout")
    argparser.add_argument(
        '-d', '--debug',
        help="Set log level to debug",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.WARNING,
    )
    argparser.add_argument(
        '-v', '--verbose',
        help="Set log level to info",
        action="store_const", dest="loglevel", const=logging.INFO,
    )

    subparser = argparser.add_subparsers(dest="command", help="The action to be taken")

    pollparser = subparser.add_parser("poll", help="Fetches data from configured sources and "
                                                   "forwards to configured output since last poll attempt")
    pollparser.add_argument("config-file", help="Absolute path to configuration file")

    historyparser = subparser.add_parser("history", help="Fetches data from specified source for "
                                                         "specified time range and forwards to configured output")
    historyparser.add_argument("config-file", help="Absolute path to configuration file")
    historyparser.add_argument("source", help="Carbon Black Cloud instance to fetch historical data")
    historyparser.add_argument("start", help="The start time in ISO 8601")
    historyparser.add_argument("end", help="The end time in ISO 8601")

    convertparser = subparser.add_parser("convert", help="Convert CBC Syslog 1.0 conf to new 2.0 toml")
    convertparser.add_argument("config-file", help="Absolute path to CBC Syslog 1.0 configuration file")
    convertparser.add_argument("--output", "-o", help="Output file location", default=".")

    setupparser = subparser.add_parser("setup", help="Setup wizard to walkthrough configuration")
    setupparser.add_argument("--output", "-o", help="Output file location", default=".")

    args = argparser.parse_args()

    log.setLevel(args.loglevel)

    if args.log_file != "stdout":
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)
    else:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(formatter)
        log.addHandler(stdout_handler)

    log.info("Carbon Black Cloud Syslog 2.0")

    try:
        for process in psutil.process_iter():
            try:
                if process.name() == "cbc-syslog.pid":
                    log.error("An instance of cbc syslog is already running")
                    sys.exit(0)
            except psutil.NoSuchProcess:
                continue
            except psutil.ZombieProcess:
                continue

        main(args)
    except Exception as e:
        log.error(e, exc_info=True)
        sys.exit(-1)
