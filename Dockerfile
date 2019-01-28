# use centos as build imagea, for rpm-build support
FROM centos:7 AS build

# set up an environment wih pip (required to get pyinstaller), and make directories used later
RUN yum update -y \
  && yum install -y epel-release \
  && yum install -y python-pip rpm-build \
  && pip install pyinstaller \
  && mkdir -p \
    /root/build-root \
    /root/cb-defense-syslog \
    /root/rpmbuild/SOURCES

# rest of our build-commands will happen here
WORKDIR /root/cb-defense-syslog

# copy source into the build image
COPY . .

# set up environment, build binary (via rpm-build), extract it
RUN pip install -r requirements.txt \
  && python setup.py -v bdist_binaryrpm \
  && cd /root/build-root \
  && rpm2cpio /root/rpmbuild/RPMS/x86_64/python-cb-defense-syslog-*.rpm | cpio -id

# set up a python runtime environment for final image
FROM python:2.7-slim AS base

# rpm installs this but it's empty so have to manually make it
RUN mkdir -p /usr/share/cb/integrations/cb-defense-syslog/store

COPY docker-entrypoint.sh /

COPY --from=build /root/build-root /

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/share/cb/integrations/cb-defense-syslog/cb-defense-syslog", "--config-file", "/etc/cb/integrations/cb-defense-syslog/cb-defense-syslog.conf", "--log-file", "/dev/stdout"]
