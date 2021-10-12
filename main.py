#!/bin/python3
import os
import time

from src.SSHBlackList import SSHBlackList
import logging
import logging.config
import traceback

from src.frps import FrpsBlackList


def main():
    logging.config.fileConfig('logging.conf')
    os.environ["TZ"] = 'Asia/Shanghai'
    time.tzset()
    logging.info('started.')
    ssh = SSHBlackList()
    frps = FrpsBlackList()
    while True:
        try:
            ssh.reinforce()
        except Exception as err:
            logging.critical(
                "exception in ssh black list reinforce, {}:\n{}".format(
                    err,
                    traceback.format_exc()
                )
            )
        try:
            frps.reinforce()
        except Exception as err:
            logging.critical(
                "exception in frps black list reinforce, {}:\n{}".format(
                    err,
                    traceback.format_exc()
                )
            )
        time.sleep(10)


if __name__ == '__main__':
    main()
