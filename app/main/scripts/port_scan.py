#!/usr/bin/env python


import nmap
#import MySQLdb
import datetime
import json
from mysql_config import conn_mysql


'''
def conn_mysql():
	conn = MySQLdb.connect(host="127.0.0.1", user="root", passwd="p@ssw0rd", db="dev_db", charset="utf8")
	return conn
'''


def scan_port(ip, ports, way):
	time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
	nm = nmap.PortScanner()
	ok_port = []
	cursor = conn_mysql().cursor()
	if type(ports) is list and "-" in ''.join(ports) or "," in ''.join(ports): 
		new_ports = []
		for port_list in  ports:
			p = port_list.split('-')
			new_ports += (range(int(p[0]), int(p[-1]) + 1))


	elif "-" in ports:
		p = ports.split('-')
		new_ports = range(int(p[0]), int(p[-1]) + 1)
	
	elif type(ports) is list: 
		new_ports = ports

	if type(ports) == list:
		ports = ','.join(ports)

	data_list = []	
	for port in new_ports:
		if way == "fast":
			info = nm.scan(ip, str(port))
		else:
			info = nm.scan(ip, str(port))
		try:
			info = nm[ip].tcp(int(port))
			ok_port.append(port)
			progress =  int(float(len(ok_port))/float(len(new_ports)) * 100)
			if info['product'] == "" or info['version'] == "":
				product,version = "None","None"
			else:
				product,version = info['product'], info['version']
			
			if info['state'] == "open":
				data_list += [[product, version, port, info['state']]]
			

			sql = "select * from report_nmap where ip='%s'" %ip

			if int(cursor.execute(sql)) == 0:
				sql = "insert into report_nmap (ip, i_time, data_t, way, port_info) values(%s,%s,%s,%s,%s)"
				param = (ip, time, progress, way, ports)
			else:
				sql = "update report_nmap set data_t=%s where ip=%s"
				param = (progress, ip)
			cursor.execute(sql, param)
		except:
			pass

	sql = "update report_nmap set data=%s, i_time=%s, way=%s, port_info=%s where ip=%s"
	param = (json.dumps(data_list), time, way, ports, ip)
	cursor.execute(sql, param)


def scan_main(ip, ports, way):
	scan_port(ip, ports, way)
		


if __name__=='__main__':
	ips = ['172.16.5.240', '172.16.5.242']
	ports = [u'10-20,60-80'] 
#	ports = ['22','3306']
	way = 'fast'
	for ip in ips:
		scan_main(ip, ports, way)
	
