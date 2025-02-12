'''
Author: lza 1342011793@qq.com
Date: 2024-11-14 16:04:51
LastEditors: lza 1342011793@qq.com
LastEditTime: 2024-11-14 17:55:19
FilePath: /MLFAD/log_parse/bash/bash_parse.py
Description: 将bash命令进行解析存入数据库中
'''
import pandas as pd
import pymysql
from sqlalchemy import create_engine
import re
from datetime import datetime

import host2ip
import cmd_parse


# 指定表名，返回所有数据
def get_origin_data(table_name):
    conn = pymysql.connect(host='10.181.7.225', port=9980,
                            user='root', passwd='S6000#249', db='ELK_data', charset='utf8mb4')
    cursor=conn.cursor()

    table = table_name
    sql = "SELECT * FROM `"+table+"`;"
    cursor.execute(sql)
    origin_data = cursor.fetchall()
    conn.close()
    return origin_data


def getDataStructure():
    return {
        "timestamp": "",
        "host": "",
        "host_ip": "",
        "username": "",
        "remote_ip": "",
        "terminal_id": "",
        "command_keyword": "",
        "parsed_args": "",
        "entity": "",
        "dip": "",
        "dport": "",
        "_raw": "",
        "command_type": "",
        "is_sensitive": "",
    }


def df2sql(data):
    engine = create_engine("mysql+pymysql://root:S6000#249@10.181.7.225:9980/ELK_data?charset=utf8mb4")
    df = pd.DataFrame(data)
    df.to_sql(f"bash_ner", con=engine, if_exists="replace", index=True)


def parse_data(table_name):
    origin_data = get_origin_data(table_name)
    parsedList = []
    newline_flag = False

    for item in origin_data:
        hostname = item[1]
        message = item[2]

        # 将配置好的bash历史命令进行解析，格式为[2024-11-11-16:11:51][root][][/dev/pts/3]ps -ef |grep sysdiga
        pattern = r'\[(.*?)\]\[(.*?)\]\[(.*?)\]\[(.*?)\](.*)'
        match = re.match(pattern, message)
        if match:
            timestamp_str, username, remote_ip, terminal_id, _raw = match.groups()
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d-%H:%M:%S")
        else:
            continue

        if _raw == "clear":
            newline_flag = False
            continue
        # 处理bash命令的换行符问题，默认换行前后的bash在日志中一定相邻
        if newline_flag == True:
            if _raw != _raw_last:
                _raw = _raw_last + _raw
        if _raw[-1] == '\\' and _raw[-2] != '\\':
            newline_flag = True
            _raw_last = _raw[:-1]
            continue
        else:
            newline_flag = False

        _raw_list = cmd_parse.split_operaters(_raw)

        host_ip = host2ip.host2ip(hostname)

        for _raw_i in _raw_list:
            dataDict = getDataStructure()
            try:
                parse_cmd = cmd_parse.Parse_cmd(_raw_i)
                command_keyword = parse_cmd.command
                parsed_args = parse_cmd.parsed_args
                parsed_entity = parse_cmd.entity
                dip = parse_cmd.dip
                dport = parse_cmd.dport
                is_sensitive = parse_cmd.sensitive
                dataDict["command_keyword"] = command_keyword
                dataDict["parsed_args"] = str(parsed_args)
                dataDict["entity"] = str(parsed_entity)
                dataDict["dip"] = dip
                dataDict["dport"] = dport
                dataDict["is_sensitive"] = is_sensitive
            except:
                command_keyword = _raw_i.split(' ')[0]
                dataDict["command_keyword"] = command_keyword
            
            dataDict["timestamp"] = timestamp
            dataDict["host"] = hostname
            dataDict["host_ip"] = host_ip
            dataDict["username"] = username
            dataDict["remote_ip"] = remote_ip
            dataDict["terminal_id"] = terminal_id
            dataDict["_raw"] = _raw_i
            dataDict["command_type"] = cmd_parse.classify_cmd(command_keyword)

            parsedList.append(dataDict)

    parsedList = sorted(parsedList, key=lambda x: x["timestamp"])
    df2sql(parsedList)

if __name__ == '__main__':
    table_name = '_var_log_bash_command_history'
    parse_data(table_name)