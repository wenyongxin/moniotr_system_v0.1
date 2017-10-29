#!/usr/bin/env python
#ecoding:utf-8
import nmap
from mysql_config import conn_mysql
import json, os
from threading import Thread

cursor = conn_mysql().cursor()

def scan_games(ip):
	try:
		nm = nmap.PortScanner()
		info = nm.scan(str(ip),arguments='-sT -p' '1-65535')
		Gudp = nm.scan(hosts=str(ip),arguments='-p 161 -sU')
		total_port = dict(info['scan'][ip]['tcp'], **udp['scan'][ip]['udp'])
		data_list = []
		for port,v in total_port.items(): 
			if v['product'] == "" or v['version'] == "":
				product,version = "None","None"
			else:
				product,version = v['product'], v['version']
			if v['state'] == "open":
				if port == 161:
					data_list += [[product, version, "udp", port, v['state']]]
				else:
					data_list += [[product, version, "tcp", port, v['state']]]
	except:
		pass
		
	sql = "update scan_group set progress=1, data=%s where ipaddr=%s"
	try:
		param = (json.dumps(data_list), ip)
	except:
		param = (json.dumps([]), ip)
	cursor.execute(sql, param)

def Thread_Ip(ips):
	threads = []
	for ip in ips:
		threads.append(Thread(target=scan_games, args=(ip,)))
		
	for threads_objects in threads:
		threads_objects.start()
	


'''用于从数据库中获取判断是否扫描完毕'''
def flush_scan():
	sql_scan_id = '''select ipaddr,data from scan_group'''
	cursor.execute(sql_scan_id)
	ips, scan_ids = [], []
	for scan in cursor.fetchall():
		ips.append(str(scan[0]))
		if str(scan[1]) != "None":
			scan_ids.append(str(scan[1]))

	cmd = '''ps axu | grep "nmap -oX" | grep -v grep | grep -v sh | wc -l'''
	np = int(os.popen(cmd).read())
	if np == 0:
		if len(ips) != len(scan_ids):
			sql_progress = '''select ipaddr from scan_group where progress = 0'''
			cursor.execute(sql_progress)
			ips = []
			for scan_ips in cursor.fetchall():
				ips.append(scan_ips[0])
			Thread_Ip(ips)

	
if __name__=="__main__":
	flush_scan()
