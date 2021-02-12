import argparse
from collections import OrderedDict
import datetime
import json
import re
import sys
import time
import numpy as np
import matplotlib.pyplot as plt
import sqlite3


#TODO
# -- look at randomness of client ports
# -- look at 0x20
# -- look at cookies / DNSSEC usage
# -- point students to BIND log information
# -- example of piping things to script

QUERY_LOG_RE = re.compile(r'^(?P<timestamp>\d+-\d+-\d+T\d+:\d+:\d+(?P<microseconds>\.\d+)?)-\d+:\d+\s(.*\s)?' + \
        r'client\s+(@0x[0-9a-f]+\s+)?(?P<client_ip>[a-fA-F0-9:\.]+)#(?P<client_port>\d+)\s(.*\s)?' + \
        r'query:\s+(?P<qname>\S+)\s+IN\s+(?P<qtype>\S+)\s+(?P<flags>\S+)' + \
        r'\s+\((?P<server_ip>[a-fA-F0-9:\.]+)\)')

def parse_log_line(line):
    m = QUERY_LOG_RE.search(line)
    if m is None:
        sys.stderr.write('Could not parse log line: %s\n' % line)
        return

    print ("*****date: ", m.group('timestamp'))
    # return get_timestamp_from_log(m.group('timestamp'), m.group('microseconds'))
    log_ts = get_timestamp_from_log(m.group('timestamp'), m.group('microseconds'))

    return OrderedDict((
            ('timestamp', log_ts),
            ('qname', m.group('qname')),
            ('qtype', m.group('qtype')),
            ('server_ip', m.group('server_ip')),
            ('client_ip', m.group('client_ip')),
            ('client_port', m.group('client_port')),
            ('flags', m.group('flags')),
            ))

def get_timestamp_from_log(ts_str, microseconds):
    ts = time.mktime(datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S").timetuple())
    if microseconds is not None:
        ts += float(microseconds)
    return ts

def clearTable():
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    # sql = '''DROP TABLE IF EXISTS march32019'''    #commented out to prevent accidental removal of the table
    cursor.execute(sql)
    connection.commit()
    connection.close()

def createTable():
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = '''CREATE TABLE march32019
            (ID INTEGER PRIMARY KEY AUTOINCREMENT,
            INITTIME INT,
            QNAME VARCHAR,
            QTYPE VARCHAR,
            SERVERIP VARCHAR,
            CLIENTIP VARCHAR,
            CLIENTPORT INT,
            FLAGS VARCHAR)'''

    cursor.execute(sql)
    connection.commit()
    connection.close()

#TODO Fix this to take a table name as an arg
def insertToDatabase(line):
    m = QUERY_LOG_RE.search(line)
    if m is None:
        sys.stderr.write('Could not parse log line: %s\n' % line)
        return
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    log_ts = get_timestamp_from_log(m.group('timestamp'), m.group('microseconds'))

    sql = "INSERT INTO march32019 (INITTIME, QNAME, QTYPE, SERVERIP, CLIENTIP, CLIENTPORT, FLAGS) " \
        f"VALUES ('{log_ts}'," \
        f"'{m.group('qname')}'," \
        f"'{m.group('qtype')}'," \
        f"'{m.group('server_ip')}'," \
        f"'{m.group('client_ip')}'," \
        f"'{m.group('client_port')}'," \
        f"'{m.group('flags')}')"
    cursor.execute(sql)
    connection.commit()
    connection.close()

def checkDatabase():
  connection = sqlite3.connect('data.db')
  cursor = connection.cursor()

  sql = "SELECT * FROM march32019"
  cursor.execute(sql)

  rows = cursor.fetchall()
  for row in rows:
    print(row)
  connection.close()

def testDatabase():
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT FLAGS, COUNT(FLAGS) FROM march32019 GROUP BY FLAGS"
    cursor.execute(sql)
    rows = cursor.fetchall()
    for row in rows:
        print(row)

    sql = "SELECT * FROM march32019 ORDER BY ID DESC LIMIT 1"
    cursor.execute(sql)
    rows = cursor.fetchall()
    for row in rows:
        print(row[0])

    sql = "SELECT COUNT(*) FROM march32019 WHERE CLIENTIP LIKE '%::%'"
    cursor.execute(sql)
    rows = cursor.fetchall()
    for row in rows:
        print(row)
    connection.close()

def getFlagCount (tableName):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT FLAGS, COUNT(FLAGS) FROM " + tableName + " GROUP BY FLAGS"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    return rows

def getTotalCount (tableName):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT * FROM " + tableName + " ORDER BY ID DESC LIMIT 1"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    return rows[0]

def getIPV6Count (tableName):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT COUNT(*) FROM " + tableName + " WHERE CLIENTIP LIKE '%::%'"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    return rows[0]

def getQTypeCount(tableName):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT QTYPE, COUNT(QTYPE) FROM " + tableName + " GROUP BY QTYPE"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    return rows

def getQNameCount(tableName, quantity):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT QNAME, COUNT(QNAME) FROM " + tableName + " GROUP BY QNAME" + " ORDER BY QNAME"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    sortedRows = sorted(rows, key=lambda k:k[1], reverse=True)
    return sortedRows[:quantity]

def getSourceIpCount (tableName, quantity):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT CLIENTIP, COUNT(CLIENTIP) FROM " + tableName + " GROUP BY CLIENTIP"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    sortedRows = sorted(rows, key=lambda k:k[1], reverse=True)
    return sortedRows[:quantity]

def getDestIpCount (tableName, quantity):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT SERVERIP, COUNT(SERVERIP) FROM " + tableName + " GROUP BY SERVERIP"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    sortedRows = sorted(rows, key=lambda k:k[1], reverse=True)
    return sortedRows[:quantity]

def getPortCount (tableName, quantity):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT CLIENTPORT, COUNT(CLIENTPORT) FROM " + tableName + " GROUP BY CLIENTPORT"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    sortedRows = sorted(rows, key=lambda k:k[1], reverse=True)
    return sortedRows[:quantity]

def main():
    # clearTable()
    # createTable()
    parser = argparse.ArgumentParser()
    parser.add_argument('logfile', type=argparse.FileType('r', encoding='utf-8'))
    args = parser.parse_args(sys.argv[1:])
    # # print(args.logfile.name)
    #
    while True:
        line = args.logfile.readline()
        line = line.rstrip()
        if not line:
            break
        insertToDatabase(line)

    # i = 0
    # while i < 5:
    #     line = args.logfile.readline()
    #     line = line.rstrip()
    #     # ipv4, ipv6 = parse_log_line(line, ipv4, ipv6)
    #     # ts = parse_log_line(line)
    #     # ts_array.append(ts)
    #     if not line:
    #         break
    #     sys.stdout.write('%s\n' % json.dumps(parse_log_line(line)))
    #     i += 1

    # print ("flags: ", getFlagCount('march32019'))
    # print("total: ", getTotalCount('march32019'))
    # print ("qtype: ", getQTypeCount('march32019'))
    # print ("IPV6 Count: ", getIPV6Count('march32019'))
    # print("qname: ", getQNameCount('march32019', 4))
    # print("clientIP: ", getSourceIpCount('march32019', 4))
    # print("serverIP: ", getDestIpCount('march32019', 4))
    # print("Ports: ", getPortCount('march32019', 4))
    # ipv6 = getIPV6Count('march32019')[0]
    # total = getTotalCount('march32019')[0]
    # print("ipv6: ", ipv6, "total: ", total )
    # ipv4 = total - ipv6
    # ipFrequencyChart(ipv4, ipv6)
    # testDatabase('march32019')
    # checkDatabase()
    # qnameFreq = getQNameCount('march32019', 8)
    # qnameFrequencyChart('march32019', qnameFreq)
    # portFreq = getPortCount('march32019', 8)
    # portFrequencyChart('march32019', portFreq)

    # analyzeTime()

def analyzeTime():
    # CONVERT(data_type(length), expression, style)
    # monday []
    # tuesday []
    # convert time to day
    # if Monday monday.append(i)

    # graph all days

    return

    # while True:
    #     line = args.logfile.readline()
    #     line = line.rstrip()
    #     insertToDatabase(line)
    #     if not line:
    #         break
    #     sys.stdout.write('%s\n' % json.dumps(parse_log_line(line)))
    # x = np.arange(0, len(ts_array), 1)
    # plt.plot(x, ts_array)
    # plt.show()

def ipFrequencyChart(ipv4, ipv6):
    ips = [('ipv4', ipv4), ('ipv6', ipv6)]
    ips, score = zip(*ips)
    x_pos = np.arange(len(ips))
    plt.bar(x_pos, score)
    plt.xticks(x_pos, ips)
    plt.show()

def qnameFrequencyChart(fileName, qnameFreq):
    dns, score = zip(*qnameFreq)
    x_pos = np.arange(len(dns))

    # slope, intercept = np.polyfit(x_pos, score, 1)
    # trendline = intercept + (slope * x_pos)
    # plt.plot (x_pos, trendline, color='red', linestyle = '--')
    plt.bar(x_pos, score, align='center')
    plt.xticks(x_pos, dns)
    plt.ylabel('Popularity')
    plt.title(fileName)
    plt.show()

def portFrequencyChart(fileName, portFreq):
    port, score = zip(*portFreq)
    x_pos = np.arange(len(port))

    # slope, intercept = np.polyfit(x_pos, score, 1)
    # trendline = intercept + (slope * x_pos)
    # plt.plot (x_pos, trendline, color='red', linestyle = '--')
    plt.plot(port, score)
    # plt.xticks(np.arange(min(port), max(port), 100))
    # plt.tick_params(
    #     axis='x',
    #     which='minor',
    #     bottom=False,
    #     labelbottom=False)
    plt.ylabel('Popularity')
    plt.title(fileName)
    plt.show()


if __name__ == '__main__':
    main()

