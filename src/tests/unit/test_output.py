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

"""Tests for the Output object."""

import pytest
import time

from cbc_syslog.util import Output


@pytest.mark.filterwarnings("ignore:Unverified HTTPS request.*")
def test_send_http():
    """Test HTTP transmission"""
    output = Output({
        "type": "http",
        "host": "https://0.0.0.0:5001/http_out",
        "tls_verify": False
    })
    success = output.send("Hello World")
    assert success is True
    assert "Hello World".encode("utf-8") == pytest.http_recv_data


def test_send_tcp():
    """Test TCP transmission"""
    output = Output({
        "type": "tcp",
        "host": "0.0.0.0",
        "port": "8887"
    })
    success = output.send("Hello World")
    assert success is True
    assert "Hello World".encode("utf-8") == pytest.tcp_recv_data


def test_send_udp():
    """Test UDP transmission"""
    output = Output({
        "type": "udp",
        "host": "0.0.0.0",
        "port": "8886"
    })
    success = output.send("Hello World")
    assert success is True

    # Add small delay to enable udp transaction to complete
    time.sleep(0.1)
    assert "Hello World".encode("utf-8") == pytest.udp_recv_data
