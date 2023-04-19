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

import pathlib
import pytest
import time

from cbc_syslog.util import Output

CERTS_PATH = pathlib.Path(__file__).joinpath("../../fixtures/certs").resolve()


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


@pytest.mark.filterwarnings("ignore:Unverified HTTPS request.*")
def test_send_http_invalid():
    """Test HTTP transmission with invalid port"""
    output = Output({
        "type": "http",
        "host": "https://0.0.0.0:1234/http_out",
        "tls_verify": False
    })
    success = output.send("Hello World")
    assert success is False


def test_send_tcp():
    """Test TCP transmission"""
    output = Output({
        "type": "tcp",
        "host": "0.0.0.0",
        "port": "8887"
    })
    success = output.send("Hello World")
    assert success is True

    # Add small delay to enable tcp transaction to complete
    time.sleep(0.1)
    assert "Hello World".encode("utf-8") == pytest.tcp_recv_data


def test_send_tcp_invalid():
    """Test TCP transmission with invalid port"""
    output = Output({
        "type": "tcp",
        "host": "0.0.0.0",
        "port": "1234"
    })
    success = output.send("Hello World")
    assert success is False


def test_send_tcp_tls():
    """Test TCP + TLS transmission"""
    output = Output({
        "type": "tcp+tls",
        "host": "localhost",
        "port": "8888",
        "ca_cert": str(CERTS_PATH.joinpath("rootCACert.pem"))
    })
    success = output.send("Hello World")
    assert success is True

    # Add small delay to enable tls handshake to complete
    time.sleep(0.1)
    assert "Hello World".encode("utf-8") == pytest.tcp_tls_recv_data


def test_send_tcp_tls_mismatch_host(caplog):
    """Test TCP + TLS transmission with mismatch host to CA cert"""
    output = Output({
        "type": "tcp+tls",
        "host": "0.0.0.0",
        "port": "8888",
        "ca_cert": str(CERTS_PATH.joinpath("rootCACert.pem"))
    })
    success = output.send("Hello World")
    assert success is False
    assert "CERTIFICATE_VERIFY_FAILED" in caplog.records[0].msg


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


def test_send_udp_invalid():
    """Test UDP transmission with invalid ip"""
    output = Output({
        "type": "udp",
        "host": "bad",
        "port": "1234"
    })
    success = output.send("Hello World")
    assert success is False


def test_send_file(wipe_tmp):
    """Test File output"""
    tmp_dir = pathlib.Path(__file__).joinpath("../../fixtures/tmp").resolve()
    output = Output({
        "type": "file",
        "file_path": tmp_dir
    })
    success = output.send("Hello World")
    assert success is True

    output_file_path = ""
    for file_path in tmp_dir.iterdir():
        if file_path.name != "KEEP_EMPTY.md":
            output_file_path = file_path

    # Read only file in tmp directory
    with output_file_path.open() as file:
        assert file.readline() == "Hello World"


def test_send_file_invalid(caplog, wipe_tmp):
    """Test File output with invalid directory"""
    output = Output({
        "type": "file",
        "file_path": "INVALID"
    })
    success = output.send("Hello World")
    assert success is False
    assert "FileNotFoundError" in caplog.records[0].msg
