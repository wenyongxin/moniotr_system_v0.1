#!/usr/bin/env python
#ecoding:utf-8

#from __future__ import print_function
from openvas_lib import VulnscanManager, VulnscanException, report_parser
from threading import Semaphore
from functools import partial
from xml.etree import ElementTree
import os, re
import sys
import urllib, urllib2, json
from mysql_config import conn_mysql
import MySQLdb
from threading import Thread


reload(sys)  
sys.setdefaultencoding('utf8')  



'''实例化数据库连接'''
cursor = conn_mysql().cursor()
save_report = r'/var/www/html/monitor/app/static/report/'
openvas_ip = '58.229.184.39'
admin_name = 'admin'
admin_password = 'admin123'

'''做英文翻译'''
def en_to_cn(english):
        if english:
                url = 'http://fanyi.youdao.com/openapi.do?keyfrom=imyours1991&key=708486460&type=data&doctype=json&version=1.1'
                data = {'q': english}
                sql = '''select * from openvas_en2cn where en="%s"''' % english.replace('\n', '')
                if int(cursor.execute(sql)) == 0:
                        res = json.loads(urllib2.urlopen(url, urllib.urlencode(data)).read())
                        if res['errorCode'] == 0:
                                sql_insert = '''insert into openvas_en2cn (en, cn) values(%s,%s)'''
                                param = (english.replace('\n', ''), res['translation'][0])
                                cursor.execute(sql_insert, param)


'''提交扫描任务'''
def run(manager, ip):
	try:
		scan_id, target_id = manager.launch_scan(target = ip, profile = "Full and very deep")
		sql = '''update openvas_report set progress=0, scan_id=%s, target_id=%s, plan=0 where ipaddr=%s'''
		param = (scan_id, target_id, ip)
		cursor.execute(sql, param)
		return 0
	except:
		return 1

'''通过获取的报告通过整理后存储到数据库中'''
def open_report(ip, filename, scan_id, target_id):
        all_info = []
        results = report_parser(filename)
        for x in results:
		info = {'id': x.id, 'nvt_name': x.nvt.name.replace('\n', ''), 'port_proto': x.port.proto, 'port_name': x.port.port_name}
		for b in x.nvt.tags[0].split('|'):
			del_n = b.split('=')[1].replace('\n', '')
			info[b.split('=')[0]] = del_n
		en_to_cn(x.nvt.name.replace('\n', ''))
		for key in ['insight', 'impact', 'affected', 'solution', 'summary', 'vuldetect']:
			en_to_cn(info.get(key))
		all_info.append(info)

	sql = '''update openvas_report set progress=1, data=%s, plan=100.0 where ipaddr=%s'''
	param = (json.dumps(all_info), ip)
	cursor.execute(sql, param)



'''将获取的报告写成xml文件'''
def write_report(report, filename):
	try:
	        fout = open(filename, "wb")
        	fout.write(ElementTree.tostring(report.find("report"), encoding='utf-8', method='xml'))
	        fout.close()
		return 0
	except:
		return 1


'''更新进度数据库语句'''
def update_plue(pro,ip):
	pro_sql = '''update openvas_report set plan=%s where ipaddr="%s"''' %(pro, ip)
	cursor.execute(pro_sql)



'''获取openvas中所有包含openvas_lib_scan关键字的任务数量'''
def get_openvas_num(manager):
	scan_task_ids = []
	for key, value in manager.get_all_scans.items():
		if "openvas_lib_scan" in key:
			scan_task_ids.append(value)
	return len(scan_task_ids)




'''删除没有执行的任务'''
def flush_openvas(manager):
	'''从数据库中刷出用户名称'''
	scan_user = '''select operation_user from openvas_report'''
	cursor.execute(scan_user)
	users = []
	for user in cursor.fetchall():
		users.append(user[0])

	user_ips = {}
	scan_ids = []
	for user in list(set(users)):
		scan_ip = u"select ipaddr,progress,scan_id from openvas_report where operation_user='%s'" %user
		cursor.execute(scan_ip)
		full_ips = cursor.fetchall()
		database_ips = []
		for ip in full_ips:
			if ip[1] == 0:
				scan_ids.append(ip[2])
		                database_ips.append(ip[0].encode('utf-8'))
		user_ips[user] = database_ips


	if get_openvas_num(manager) == 0:
		print u'openvas 没有扫描任务'
	else:

		'''用于判断哪些IP需要执行漏洞扫描'''
		for u,i in user_ips.items():
			if len(i) == 0:
				print u'%s:\t扫描已经结束' %u
	                       	'''删除完成的'''
				sql = "select ipaddr,scan_id,target_id from openvas_report where operation_user='%s'" %u
				cursor.execute(sql)
				for info in cursor.fetchall():
					try:
						print u'删除 %s' %info[0]
						manager.delete_scan(info[1].encode('utf-8'))
						manager.delete_target(info[2].encode('utf-8'))
					except:
						print u'删除 %s 异常' %info[0]

			else:
				print u'%s:\t%s的IP没有扫描' %(u,len(i))
				openvas_ips = []
				for total_openvas in manager.get_all_scans.items():
					if type(total_openvas[0]).__name__ == 'str':
						for scan_id in scan_ids:
							if total_openvas[1] == scan_id:
								openvas_ips.append(total_openvas[0].split('_')[3].encode('utf-8'))
				print u'openvas 扫描的IP任务数:%s' %len(openvas_ips)
			
		
				data_sql = "select ipaddr,progress,scan_id,target_id from openvas_report where progress=0 and operation_user='%s'" %u
				cursor.execute(data_sql)
				progress_data = cursor.fetchall()


				'''数据库中的IP大于openvas中扫描的IP数量'''	
				if len(i) > len(openvas_ips) and len(progress_data) !=0:
					print u'数据库中的IP大于openvas中扫描的IP数量'
					sql = '''select ipaddr,scan_id from openvas_report'''
					cursor.execute(sql)
					for info in cursor.fetchall():
						if not info[1]:
							if run(manager, info[0].encode('utf-8')) == 0:
								print u'策略1: %s ok' %info[0].encode('utf-8')


					'''刷新进度如果进度100则生成报告'''
				elif len(progress_data) > 0:
					print u'刷新进度如果进度100则生成报告'
					for progress in progress_data:
						try:
							scan_ip,db_progress,scan_id,target_id = progress[0].encode('utf-8'),progress[1],progress[2].encode('utf-8'),progress[3].encode('utf-8')
							pro = manager.get_progress(scan_id)
							filename = '%s%s.xml' % (save_report, scan_ip)
							if pro < 100.0:
								update_plue(pro, scan_ip)
								print u'%s 进度已经更新 %s %%' %(scan_ip,pro)
							elif pro == 100.0:
								if db_progress != 1:
									try:
				                	        	        report_id = manager.get_report_id(scan_id)
			        	                	        	report = manager.get_report_xml(report_id)
									except:
										pass
		        	        	                if write_report(report, filename) == 0:
    		   	        	         	                open_report(scan_ip, filename, scan_id, target_id)
	        	                	        	        print '%s 获取报告完毕' %scan_ip
		        	                	        else:
        		        	                	        print u'%s 获取报告异常' %scan_ip
							else:
								print u'%s 报告已经生成' %scan_ip
						except:
							pass
	

		
	

'''view提交任务使用多线程提交任务'''
def Thread_openvas(ips):
	manager = VulnscanManager(openvas_ip, admin_name, admin_password, 9390, 300)
	for ip in ips:
		run(manager, ip)
		





if __name__ == '__main__':
	manager = VulnscanManager(openvas_ip, admin_name, admin_password, 9390, 300)
	flush_openvas(manager)
