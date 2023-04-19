The tmp directory must be kept empty to enable multiple test executions and prevent interference between tests.

conftest.py contains a fixture wipe_tmp which will erase all files except KEEP_EMPTY.md include in test parameters to reset directory
