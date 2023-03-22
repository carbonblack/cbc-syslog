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

"""Tests for the Config object."""

import pytest
import pathlib
from cbc_syslog.util import Config

FIXTURES_PATH = pathlib.Path(__file__).joinpath("../../fixtures").resolve()


@pytest.mark.parametrize("file_path, valid", [
    (str(FIXTURES_PATH.joinpath("cef.conf")), True)
])
def test_validate(file_path, valid):
    """Test Validate"""
    config = Config(file_path)
    assert config.validate()
