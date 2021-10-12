import datetime
import os
import logging
import traceback

from src import iptables
from src.BlackList import BlackList

log_filename = "/var/log/frps/frps_raspi4b.log"


class FrpsBlackList(BlackList):

    def __init__(self):
        super().__init__("frps_black_list.json")

    def add(self, ip, record):
        # 本地IP不能加入黑名单。
        if ip == "127.0.0.1":
            return

        # 如果已经处理过的记录或者已经在黑名单，不重复处理
        if self.is_in_record(ip, record) or iptables.has(ip):
            return

        self._add_to_black_list(ip, record)
        self.save()

    def reinforce(self):
        if not os.path.exists(log_filename):
            return
        records = {}
        try:
            with open(log_filename, "r+") as f:
                for line in f.readlines():
                    if "get a user connection" not in line:
                        continue
                    items = line.split()
                    action_time = items[1]
                    address = items[-1]
                    ip = address.split(":")[0]
                    ip = ip.replace('[', '')
                    if ip in records.keys():
                        last_time = records[ip]["date"][-1]
                        last_time = datetime.datetime.strptime(last_time, "%H:%M:%S")
                        records[ip]["date"].append(action_time)
                        action_time = datetime.datetime.strptime(action_time, "%H:%M:%S")
                        if (action_time - last_time).total_seconds() < 3 or\
                                len(records[ip]["date"]) >= 30:
                            self.add(ip, line)
                    else:
                        records[ip] = {
                            "date": [action_time],
                            "record": [line]
                        }
        except Exception as err:
            logging.critical("{} {}".format(err, traceback.format_exc()))

        # 解禁初犯的IP，有可能是输入错误导致的
        for ip in self.data.keys():
            # 如果超出容忍次数，不再解禁
            if self.data[ip]["count"] >= self.max_times:
                continue
            # 如果低于封锁时间，也不解禁
            last_datetime = self.data[ip]["datetime"][-1]
            dt = datetime.datetime.now() - datetime.datetime.strptime(last_datetime, "%Y-%m-%d %H:%M:%S")
            # 封锁时间根据封锁次数累加
            if dt.total_seconds() <= self.every_time_black_seconds * self.data[ip]["count"]:
                continue
            iptables.remove(ip)
