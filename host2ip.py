'''
Author: lza 1342011793@qq.com
Date: 2024-11-13 18:14:03
LastEditors: lza 1342011793@qq.com
LastEditTime: 2024-11-30 16:51:11
FilePath: /MLFAD/log_parse/bash/host2ip.py
Description: 靶场采集数据集主机名和IP地址的对应
'''
host_dict = {
    'dataset': '192.168.9.101',
    'user1': '192.168.9.102',
    'web': '192.168.9.103',
    'user2': '192.168.9.104',
    'reverseProxy': '192.168.9.105'
}

def host2ip(host):
    ip = host_dict[host]
    return ip


def ip2host(ip):
    for key, value in host_dict.items():
        if value == ip:
            return key
    return "unknown"