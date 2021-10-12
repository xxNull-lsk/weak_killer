import logging
import os


def add(ip):
    ret = os.system("iptables -I INPUT -s {} -j DROP".format(ip))
    if ret == 0:
        return True
    return False


def has(ip):
    ret = os.system("iptables -L -n | grep {} | grep DROP | grep all".format(ip))
    if ret == 0:
        return True
    return False


def remove(ip):
    cmd = "iptables -L -n --line-numbers | grep {} | grep DROP | grep all".format(ip)
    r = os.popen(cmd)
    for line in r.readlines():
        # 1    DROP       all  --  0.0.0.0/0            0.0.0.0/0
        logging.info("Remove {} from iptables, record: {}".format(line, ip))
        os.system("iptables -D INPUT -s {} -j DROP".format(ip))
    r.close()
