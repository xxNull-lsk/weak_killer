#!/bin/python3
import os
import time

from src.user import BlackList
import logging
import logging.config
import traceback


def main():
    logging.config.fileConfig('logging.conf')
    os.environ["TZ"] = 'Asia/Shanghai'
    time.tzset()
    logging.info('started.')
    bl = BlackList()
    while True:
        try:
            bl.reinforce()
        except Exception as err:
            logging.critical(
                "exception in reinforce_user, {}:\n{}".format(
                    err,
                    traceback.format_exc()
                )
            )
        time.sleep(10)


if __name__ == '__main__':
    main()
