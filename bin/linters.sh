#!/bin/sh

set -e

echo 'Running flake8....'
flake8 --docstring-convention google src/cbc_syslog/
flake8 --docstring-convention google src/tests/
