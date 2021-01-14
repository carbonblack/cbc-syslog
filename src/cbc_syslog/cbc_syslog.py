import sys
import argparse
import logging
import logging.handlers
import psutil

from util.config import parse_config, verify_config
from util.forwarder import send_stored_data, send_new_data
from util.resource_fetcher import fetch_audit_logs, fetch_notification_logs

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def main(args):
    # Parse config file
    config = parse_config(args.config_file)

    # verify the config file and get the Carbon Black Cloud Server list
    output_params, server_list = verify_config(config)

    # Store Forward.  Attempt to send messages that have been saved due to a failure to reach the destination
    send_stored_data(output_params)

    logger.info("Found {0} Carbon Black Cloud Servers in config file".format(len(server_list)))

    # Iterate through our Carbon Black Cloud Server list
    for server in server_list:
        logger.info("Handling notifications for {0}".format(server.get('server_url')))

        notification_logs = fetch_notification_logs(server,
                                                    output_params['output_format'],
                                                    output_params['policy_action_severity'])

        logger.info("Sending Notifications")
        send_new_data(output_params, notification_logs)
        logger.info("Done Sending Notifications")

        audit_logs = fetch_audit_logs(server, output_params['output_format'])

        logger.info("Sending Audit Logs")
        send_new_data(output_params, audit_logs)
        logger.info("Done Sending Audit Logs")


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--config-file', '-c', help="Absolute path to configuration file")
    argparser.add_argument('--log-file', '-l', help="Log file location")

    args = argparser.parse_args()
    if not args.config_file:
        logger.error("a config file must be supplied")
        sys.exit(-1)

    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
        syslog_handler.setFormatter(formatter)

        logger.addHandler(syslog_handler)

    logger.info("Carbon Black Cloud Syslog 2.0")

    try:
        for process in psutil.process_iter():
            try:
                if process.name() == 'cbc-syslog.pid':
                    logger.error("An instance of cbc syslog is already running")
                    sys.exit(0)
            except psutil.NoSuchProcess:
                continue
            except psutil.ZombieProcess:
                continue

        main(args)
    except Exception as e:
        logger.error(e, exc_info=True)
        sys.exit(-1)
