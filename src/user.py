import datetime
import json
import os
import logging
import traceback


def get_local_user_info(name):
    with open("/etc/passwd", "r") as f:
        for line in f.readlines():
            items = line.split(":")
            if name != items[0]:
                continue
            # 0: user name
            # 1: user type?
            # 2: uid
            # 3: gid
            # 4: disc
            # 5: home path
            # 6: shell
            info = {
                "name": items[0],
                "uid": int(items[2]),
                "gid": int(items[3]),
                "desc": items[4],
                "home": items[5],
                "shell": items[6]
            }
            return True, info

    return False, None


class BlackList:
    max_times = 3           # 最大容忍次数，不包含
    every_time_black_seconds = 60   # 每次最大封禁时间，单位：秒
    data = {}
    folder = "/var/weak_killer"
    filename = "black_list.json"

    def __init__(self):
        self.load()

    def add(self, ip, user, record):
        # 本地IP不能加入黑名单。
        if ip == "127.0.0.1":
            return

        # 如果登陆的是本地用户不加入黑名单。
        is_local_user, info = get_local_user_info(user)
        if is_local_user and info["uid"] >= 1000:
            return

        # 如果已经在黑名单中，不重复加入
        if self.is_in_black_list(ip, record):
            return

        self._add_to_black_list(ip, record)
        self.save()

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
                    "count": 0,
                    "datetime": [now],
                    "record": [record]
                }
        logging.log(logging.INFO, "Add {} to iptables".format(ip))
        os.system("iptables -I INPUT -s {} -j DROP".format(ip))

    def is_in_black_list(self, ip, record):
        if ip in self.data.keys() and record in self.data[ip]["record"]:
            return True
        # 如果已经在黑名单中，不重复加入
        ret = os.system("iptables -L -n | grep {} | grep DROP | grep all".format(ip))
        if ret == 0:
            if ip in self.data.keys():
                return True
        return False

    @staticmethod
    def _remove_from_black_list(ip):
        cmd = "iptables -L -n --line-numbers | grep {} | grep DROP | grep all".format(ip)
        r = os.popen(cmd)
        for line in r.readlines():
            # 1    DROP       all  --  0.0.0.0/0            0.0.0.0/0
            logging.info("Remove {} from iptables, record: {}".format(line, ip))
            os.system("iptables -D INPUT -s {} -j DROP".format(ip))
        r.close()

    def reinforce(self):
        try:
            cmd = "lastb -xF | head"
            with os.popen(cmd) as f:
                for line in f.readlines():
                    items = line.split()
                    user = items[0]
                    ip = items[2]
                    self.add(ip, user, line)
        except Exception as err:
            logging.critical("{} {}".format(err, traceback.format_exc()))

        # 解禁初犯的IP，有可能是输入错误导致的
        for ip in self.data.keys():
            if self.data[ip]["count"] < self.max_times:
                last_datetime = self.data[ip]["datetime"][-1]
                dt = datetime.datetime.now() - datetime.datetime.strptime(last_datetime, "%Y-%m-%d %H:%M:%S")
                if dt.total_seconds() > self.every_time_black_seconds * self.data[ip]["count"]:
                    self._remove_from_black_list(ip)

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
