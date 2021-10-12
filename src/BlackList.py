import datetime
import json
import logging
import os
import traceback

from src import iptables


class BlackList:
    data = {}
    folder = "/var/weak_killer"
    max_times = 3           # 最大容忍次数，不包含
    every_time_black_seconds = 60   # 每次最大封禁时间，单位：秒

    def __init__(self, filename):
        self.filename = filename
        self.load()

    def save(self):
        if not os.path.exists(self.folder):
            os.makedirs(self.folder)
        with open(os.path.join(self.folder, self.filename), "w+") as f:
            data = {
                "max_times": self.max_times,
                "every_time_black_seconds": self.every_time_black_seconds,
                "data": self.data
            }
            f.write(json.dumps(data, indent=4, ensure_ascii=False))

    def load(self):
        full_filename = os.path.join(self.folder, self.filename)
        if not os.path.exists(full_filename):
            return
        try:
            with open(full_filename, "r") as f:
                txt = f.read()
                data = json.loads(txt)
                if "data" in data:
                    self.data = data["data"]
                if "max_times" in data:
                    self.max_times = data["max_times"]
                if "every_time_black_seconds" in data:
                    self.every_time_black_seconds = data["every_time_black_seconds"]
                    if self.every_time_black_seconds < 0:
                        self.every_time_black_seconds = 1
        except Exception as err:
            logging.critical("load black list failed!{}\n{}".format(err, traceback.format_exc()))

        for ip in self.data.keys():
            if self.data[ip]["count"] >= self.max_times:
                self._add_to_black_list(ip)

    def _add_to_black_list(self, ip, record=None):
        if record is not None:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if ip in self.data.keys():
                ip_info = self.data[ip]
                ip_info["count"] += 1
                ip_info["datetime"].append(now)
                ip_info["record"].append(record)
            else:
                self.data[ip] = {
                    "count": 1,
                    "datetime": [now],
                    "record": [record]
                }
        ret = iptables.add(ip)
        logging.log(logging.INFO, "Add {} to iptables, ret={}".format(ip, ret))
        return ret

    def is_in_record(self, ip, record):
        if ip in self.data.keys() and record in self.data[ip]["record"]:
            return True
        return False
