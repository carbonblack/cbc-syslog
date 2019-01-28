#!/bin/sh

if [ ! -f /etc/cb/integrations/cb-defense-syslog/cb-defense-syslog.conf ]; then
  echo "ERROR: no configuration file available, did you forget to mount one in the container?"
  exit 1
fi

exec "$@"
