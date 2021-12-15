import datetime
import ipaddress
import json
import logging
import os
import traceback
import requests
from src import iptables


def is_lan(ip):
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except:
        return False


def get_ip_address(ip):
    try:
        response = requests.get("http://ip-api.com/json/{}?lang=zh-CN".format(ip))
        response = response.json()
        if response['status'] == 'success':
            result = {
                "resultcode": "200",
                "reason": "查询成功",
                "error_code": 0,
                "result": {
                    "Country": response['country'],
                    "Province": response['regionName'],
                    "City": response['city'],
                    "District": response['org'],
                    "Isp": response['isp']
                }
            }
            return result
    except Exception as err:
        logging.critical("get ip from ip-api.com failed!{}\n{}".format(err, traceback.format_exc()))

    try:
        response = requests.get("http://apis.juhe.cn/ip/ipNewV3?ip={}&key=929125b83940756c670b461ead4f1615".
                                format(ip)).json()
        if response["resultcode"] == "200" and response["error_code"] == 0:
            return response
    except Exception as err:
        logging.critical("get ip from juhe.cn failed!{}\n{}".format(err, traceback.format_exc()))

    try:
        response = requests.get("https://ip.taobao.com/outGetIpInfo?ip={}".format(ip)).json()
        if response['code'] == 0:
            data = response['data']
            result = {
                "resultcode": "200",
                "reason": "查询成功",
                "error_code": 0,
                "result": {
                    "Country": data['country'],
                    "Province": data['region'],
                    "City": data['city'],
                    "District": data['area'],
                    "Isp": data['isp']
                }
            }
            return result
    except Exception as err:
        logging.critical("get ip from ip.taobao.com failed!{}\n{}".format(err, traceback.format_exc()))

    return {
        "resultcode": "500",
        "reason": "查询失败",
        "error_code": 1
    }


class BlackList:
    data = {}
    folder = "/var/weak_killer"
    max_times = 3           # 最大容忍次数，不包含
    every_time_black_seconds = 60   # 每次最大封禁时间，单位：秒
    cfg = {}

    def __init__(self, filename, type_name):
        self.filename = filename
        self.type = type_name
        self.load()

    def save(self):
        if not os.path.exists(self.folder):
            os.makedirs(self.folder)
        with open(os.path.join(self.folder, self.filename), "w+") as f:
            data = {
                "max_times": self.max_times,
                "every_time_black_seconds": self.every_time_black_seconds,
                "cfg": self.cfg,
                "data": self.data
            }
            f.write(json.dumps(data, indent=4, ensure_ascii=False))

    def load(self):
        logging.info("load {}".format(self.filename))
        full_filename = os.path.join(self.folder, self.filename)
        if not os.path.exists(full_filename):
            self.save()
            return
        try:
            with open(full_filename, "r") as f:
                txt = f.read()
                data = json.loads(txt)

                if "data" in data:
                    self.data = data["data"]
                if "cfg" in data:
                    self.cfg = data["cfg"]
                    if "skip" not in self.cfg:
                        self.cfg["skip"] = []
                if "max_times" in data:
                    self.max_times = data["max_times"]
                if "every_time_black_seconds" in data:
                    self.every_time_black_seconds = data["every_time_black_seconds"]
                    if self.every_time_black_seconds < 0:
                        self.every_time_black_seconds = 1

        except Exception as err:
            logging.critical("load black list failed!{}\n{}".format(err, traceback.format_exc()))

        changed = False
        for ip in self.data.keys():
            try:
                if "address" not in self.data[ip].keys() or self.data[ip]["address"]["resultcode"] != "200":
                    self.data[ip]["address"] = get_ip_address(ip)
                    changed = True
                address = self.data[ip]["address"]
                if "result" in address and address["result"]:
                    result = address["result"]
                    if ("Province" in result and result["Province"] in self.cfg['skip']) or\
                            ("City" in result and result["City"] in self.cfg['skip']):
                        continue
                if self.data[ip]["count"] >= self.max_times:
                    self._add_to_black_list(ip)

            except Exception as err:
                logging.critical("load black list failed!{}\n{}".format(err, traceback.format_exc()))
        if changed:
            self.save()

    def _add_to_black_list(self, ip, record=None):
        if record is not None:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if ip in self.data.keys():
                ip_info = self.data[ip]
                ip_info["count"] += 1
                ip_info["datetime"].append(now)
                ip_info["record"].append(record)
                if 'webhook_url' in self.cfg:
                    param = self.data[ip]["address"]["result"]
                    param['ip'] = ip
                    url = self.cfg["webhook_url"].format(**param)
                    requests.get(url)
            else:
                address = get_ip_address(ip)
                if "result" in address and address["result"]:
                    result = address["result"]
                    if ("Province" in result and result["Province"] in self.cfg['skip']) or\
                            ("City" in result and result["City"] in self.cfg['skip']):
                        return False
                self.data[ip] = {
                    "count": 1,
                    "datetime": [now],
                    "record": [record],
                    "address": address
                }
                if 'webhook_url' in self.cfg:
                    param = address["result"]
                    param['ip'] = ip
                    param['type'] = self.type
                    url = self.cfg["webhook_url"].format(**param)
                    requests.get(url)
        ret = iptables.add(ip)
        logging.log(logging.INFO, "Add {} to iptables from {}, ret={}, address={}".format(
            ip,
            self.type,
            ret,
            json.dumps(self.data[ip]["address"]["result"], ensure_ascii=False)
        ))
        return ret

    def is_in_record(self, ip, record):
        if ip in self.data.keys() and record in self.data[ip]["record"]:
            return True
        return False
