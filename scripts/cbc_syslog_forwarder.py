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
import logging
import logging.handlers
import psutil
import sys

from cbc_syslog import poll, check
from cbc_syslog.util import Config

log = logging.getLogger(__name__)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")


def main(args):
    """Core CBC Syslog Forwarder Commands"""
    config = Config(args.config_file)

    if args.command == "poll":
        succeeded = poll(config)

    elif args.command == "check":
        succeeded = check(config, args.force)
    # elif args.command == "history":
    # elif args.command == "convert":
    # elif args.command == "setup":
    else:
        log.error("Command not recognized use --help for more information on supported commands")
        sys.exit(0)

    if not succeeded:
        sys.exit(0)


if __name__ == "__main__":
    """
    CLI interface
         --log-file

        poll
            config_file
        history
            config_file
            source
            start
            end
        convert
            config_file
            --output
        setup
            --output
        check
            config_file
            --force
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
    pollparser.add_argument("config_file", help="Absolute path to configuration file")

    historyparser = subparser.add_parser("history", help="Fetches data from specified source for "
                                                         "specified time range and forwards to configured output")
    historyparser.add_argument("config_file", help="Absolute path to configuration file")
    historyparser.add_argument("source", help="Carbon Black Cloud instance to fetch historical data")
    historyparser.add_argument("start", help="The start time in ISO 8601")
    historyparser.add_argument("end", help="The end time in ISO 8601")

    convertparser = subparser.add_parser("convert", help="Convert CBC Syslog 1.0 conf to new 2.0 toml")
    convertparser.add_argument("config_file", help="Absolute path to CBC Syslog 1.0 configuration file")
    convertparser.add_argument("--output", "-o", help="Output file location", default=".")

    setupparser = subparser.add_parser("setup", help="Setup wizard to walkthrough configuration")
    setupparser.add_argument("--output", "-o", help="Output file location", default=".")

    checkparser = subparser.add_parser("check", help="Check config for valid API keys with correct permissions")
    checkparser.add_argument("config_file", help="Absolute path to configuration file")
    checkparser.add_argument("--force", action="store_true", help="Whether to force test which may cause data loss e.g. Audit Logs")

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
