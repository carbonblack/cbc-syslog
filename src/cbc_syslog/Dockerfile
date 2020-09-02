# use centos as build imagea, for rpm-build support
FROM centos:7 AS build

WORKDIR /app

# copy source into the build image
COPY . .

# set up an environment wih pip (required to get pyinstaller), and make directories used later
RUN yum update -y
RUN yum install -y epel-release
RUN yum install -y python-pip
RUN yum install -y python-devel
RUN yum -y install gcc
RUN pip install --upgrade pip
RUN pip install cbc-syslog
