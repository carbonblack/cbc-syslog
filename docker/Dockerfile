# use centos as build imagea, for rpm-build support
FROM centos:7 AS build

# set up an environment wih pip (required to get pyinstaller), and make directories used later
RUN yum update -y \
  && yum install -y gcc python-devel \
  && yum install -y epel-release \
  && yum install -y python-pip rpm-build \
  && pip install --upgrade "pip<21.0.0" \
  && pip install pyinstaller==3.5 \
  && mkdir -p \
    /root/build-root \
    /root/cbc-syslog \
    /root/rpmbuild/SOURCES

# rest of our build-commands will happen here
WORKDIR /root/cbc-syslog

# copy source into the build image
COPY . .

# set up environment, build binary (via rpm-build), extract it
RUN pip install --upgrade pip setuptools \
  && pip install -r requirements.txt \
  && python setup.py -v bdist_rpm \
  && cd /root/build-root \
  && rpm2cpio /root/cbc-syslog/dist/cbc_syslog-*.noarch.rpm | cpio -id

# set up a python runtime environment for final image
FROM python:2.7-slim AS base

# rpm installs this but it's empty so have to manually make it
RUN mkdir -p /usr/share/cb/integrations/cbc-syslog/store

COPY docker/docker-entrypoint.sh /

COPY --from=build /root/build-root /

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/share/cb/integrations/cbc-syslog/cbc-syslog", "--config-file", "/etc/cb/integrations/cbc-syslog/cbc-syslog.conf", "--log-file", "/dev/stdout"]
