import datetime
import os
import logging
import traceback
from src import iptables
from src.BlackList import BlackList, is_lan


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


class SSHBlackList(BlackList):
    last_count = 0

    def __init__(self):
        super().__init__("ssh_black_list.json", "ssh")

    def add(self, ip, user, record):
        # 本地IP不能加入黑名单。
        if is_lan(ip):
            return

        # 如果登陆的是本地用户不加入黑名单。
        is_local_user, info = get_local_user_info(user)
        if is_local_user and info["uid"] >= 1000:
            return

        # 如果已经处理过的记录或者已经在黑名单，不重复处理
        if self.is_in_record(ip, record) or iptables.has(ip):
            return

        self._add_to_black_list(ip, record)
        self.save()

    def reinforce(self):
        try:
            cmd = "lastb -xF | head"
            with os.popen(cmd) as f:
                for index, line in enumerate(f.readlines()):
                    if index < self.last_count:
                        continue
                    self.last_count = index
                    items = line.split()
                    user = items[0]
                    ip = items[2]
                    self.add(ip, user, line)
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
