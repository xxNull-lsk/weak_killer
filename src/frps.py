import datetime
import os
import logging
import traceback

from src import iptables
from src.BlackList import BlackList, is_lan


class FrpsBlackList(BlackList):
    last_count = 0

    def __init__(self):
        self.cfg["log_filename"] = "/var/log/frps/frps_raspi4b.log"
        self.cfg["max_connection_count"] = 50
        self.cfg["tick_seconds"] = 2
        self.cfg["min_count"] = 10
        super().__init__("frps_black_list.json", "frps")

    def add(self, ip, record):
        # 本地IP不能加入黑名单。
        if is_lan(ip):
            return

        # 如果已经处理过的记录或者已经在黑名单，不重复处理
        if self.is_in_record(ip, record) or iptables.has(ip):
            return

        self._add_to_black_list(ip, record)
        self.save()

    def reinforce(self):
        if not os.path.exists(self.cfg["log_filename"]):
            return
        records = {}
        try:
            with open(self.cfg["log_filename"], "r") as f:
                for index, line in enumerate(f.readlines()):
                    if index < self.last_count:
                        continue
                    self.last_count = index
                    if "get a user connection" not in line:
                        continue
                    if "ssh" not in line and "vnc" not in line and "rdp" not in line:
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
                        records[ip]["sec"] += (action_time - last_time).total_seconds()
                        count = len(records[ip]["date"])
                        if (count > self.cfg["min_count"] and records[ip]["sec"] / count < self.cfg["tick_seconds"]) or \
                                count >= self.cfg["max_connection_count"]:
                            self.add(ip, line)
                    else:
                        records[ip] = {
                            "date": [action_time],
                            "record": [line],
                            "sec": 0
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
