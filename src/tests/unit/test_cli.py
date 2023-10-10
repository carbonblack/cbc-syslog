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

"""Tests for the CLI interface."""

import pathlib
import pytest

from cbc_syslog import main
from cbc_syslog.util import Config

CONFS_PATH = pathlib.Path(__file__).joinpath("../../fixtures/confs").resolve()


@pytest.mark.parametrize("args, command, expected_args", [
    (["cbc_syslog_forwarder", "poll", str(CONFS_PATH.joinpath("template.toml"))], "poll", (Config,)),
    (["cbc_syslog_forwarder",
      "history",
      str(CONFS_PATH.joinpath("template.toml")),
      "2023-07-01T00:00:00.000000Z",
      "2023-07-05T00:00:00.000000Z",
      "--source",
      "Source1"
      ], "history",
     (Config, "2023-07-01T00:00:00.000000Z", "2023-07-05T00:00:00.000000Z", "Source1")),
    (["cbc_syslog_forwarder",
      "history",
      str(CONFS_PATH.joinpath("template.toml")),
      "2023-07-01T00:00:00.000000Z",
      "2023-07-05T00:00:00.000000Z",
      ], "history",
     (Config, "2023-07-01T00:00:00.000000Z", "2023-07-05T00:00:00.000000Z", None)),
    (["cbc_syslog_forwarder",
      "convert",
      "old.ini",
      "new.toml",
      ], "convert",
     ("old.ini", "new.toml")),
    (["cbc_syslog_forwarder",
      "setup",
      "new.toml",
      ], "wizard",
     ("new.toml",)),
    (["cbc_syslog_forwarder",
      "check",
      str(CONFS_PATH.joinpath("template.toml")),
      "--force",
      ], "check",
     (Config, True))])
def test_cli(args, command, expected_args, monkeypatch):
    """Test cli"""
    correct_command_called = False

    def patched_command(*args):
        """Patched command"""
        nonlocal correct_command_called
        nonlocal expected_args

        correct_command_called = True

        if isinstance(args[0], Config) and expected_args[0] is Config:
            args = list(args)
            expected_args = list(expected_args)
            del args[0]
            del expected_args[0]

        assert expected_args == args

        return True

    monkeypatch.setattr("sys.argv", args)
    monkeypatch.setattr(f"cbc_syslog.cli.{command}", patched_command)

    main()

    assert correct_command_called
