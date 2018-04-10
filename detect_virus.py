#!/usr/bin/python
import csv
from vtlite import *
import time


def read_csv():
    count = 0
    # with open("test.csv", "r") as source_csvfile, open("result.csv", "a+") as result_csvfile:
    with open("part2.csv", "r") as source_csvfile, open("result.csv", "a+") as result_csvfile:
        reader = csv.reader(source_csvfile)
        writer = csv.writer(result_csvfile)
        writer.writerow(["index", "md5", "Qihoo-360", "Rising", "Baidu", "Tencent", "Kaspersky", "ESET-NOD32"])
        for line in reader:
            if line[1] != 'Count' and line[0] != '':
                md5 = line[0]
                is_virus, detection = searchMD5(md5)
                if is_virus:
                    count += 1
                    detection[0] = count
                    detection[1] = md5
                    writer.writerow(detection)


def searchMD5(md5):
    time.sleep(16)
    print 'now md5 is:'
    print md5
    vt = vtAPI()
    is_virus = False
    detection = ['', '', '', '', '', '', '', '']  # [index, md5, Qihoo-360, Rising, Baidu, Tencent, Kaspersky, ESET-NOD32]
    try:
        result = vt.getReport(md5)
        if result['response_code'] == 0:
            print md5 + " -- Not Found in VT"
            return is_virus, detection
        else:
            if 'Qihoo-360' in result['scans'] and result['scans']['Qihoo-360']['result']:
                detection[2] = result['scans']['Qihoo-360']['result']
                is_virus = True
            if 'Rising' in result['scans'] and result['scans']['Rising']['result']:
                detection[3] = result['scans']['Rising']['result']
                is_virus = True
            if 'Baidu' in result['scans'] and result['scans']['Baidu']['result']:
                detection[4] = result['scans']['Baidu']['result']
                is_virus = True
            if 'Tencent' in result['scans'] and result['scans']['Tencent']['result']:
                detection[5] = result['scans']['Tencent']['result']
                is_virus = True
            if 'Kaspersky' in result['scans'] and result['scans']['Kaspersky']['result']:
                detection[6] = result['scans']['Kaspersky']['result']
                is_virus = True
            if 'ESET-NOD32' in result['scans'] and result['scans']['ESET-NOD32']['result']:
                detection[7] = result['scans']['ESET-NOD32']['result']
                is_virus = True

            return is_virus, detection
    except Exception, e:
        print 'error========='
        print e
        print md5
        return is_virus, detection


if __name__ == '__main__':
    read_csv()
