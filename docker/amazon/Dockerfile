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
FROM amazonlinux:latest
LABEL org.opencontainers.image.authors="cb-developer-network@vmware.com"

COPY . /app
WORKDIR /app

RUN yum -y install git
RUN yum -y install python3-devel
RUN yum -y install python3-pip
RUN pip3 install setuptools
RUN pip3 install -r requirements.txt
RUN pip3 install .
