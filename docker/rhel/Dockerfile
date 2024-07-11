# *******************************************************
# Copyright (c) Broadcom, Inc. 2020-2024. All Rights Reserved. Carbon Black.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.
FROM registry.access.redhat.com/ubi8/ubi:latest
LABEL org.opencontainers.image.authors="cb-developer-network@vmware.com"

COPY . /app
WORKDIR /app

RUN dnf install -y redhat-rpm-config gcc libffi-devel python-devel openssl-devel
RUN pip3 install --upgrade pip
RUN pip3 install .[test]
