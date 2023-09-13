FROM opensuse/tumbleweed
LABEL org.opencontainers.image.authors="cb-developer-network@vmware.com"

COPY . /app
WORKDIR /app

RUN zypper --non-interactive install python3-devel
RUN zypper --non-interactive install python3-pipx
RUN zypper --non-interactive install gcc
RUN pipx install -r requirements.txt
RUN pipx install .
