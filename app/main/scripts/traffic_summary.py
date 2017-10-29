#!/usr/bin/env python
#ecoding:utf-8

from mysql_config import conn_mysql
from zabbix_api import zabbix_login, get_json_obj, get_hostname
from collections import defaultdict
import time
import numpy as np

local_timestamp = int(time.time())
six_ago = local_timestamp - 21600



cursor = conn_mysql().cursor()
'''用于从数据库中获取zabbix的登录信息'''
def get_zabbix_login():
	sql = '''select zabbix_server,zabbix_user,zabbix_password from zabbixinfo where zabbix_info = "formal"'''
	cursor.execute(sql)
	return cursor.fetchall()[0]


'''通过zabbixAPI 获取hostgroup名字'''
def editor_hostgroup(a):
	ids = {}
	for key,value in get_hostname(a).items():
		if "IDC" in value and u"统计" in value:
			ids[key] = value.split('_')[1]
	return ids


'''通过hostgroupid的值获取下面所有的主机信息'''
def editor_hosts(a, groupids):
	groups_hostids = {}
	for groupid in groupids:
	        params = {"output": "extend", "groupids": groupid, "selectHosts":["hostid", "name"]}
        	method = "hostgroup.get"
	        get_obj = get_json_obj(method,params)
        	get_content = a.postRequest(get_obj)
        	for hosts in get_content['result']:
			hostids = []
			for host in hosts['hosts']:
				hostids.append(host['hostid'])
			groups_hostids[groupid] = hostids
	return groups_hostids


'''通过hostid与itemid获取itemid对应的每一分数据'''
def editor_history(a, hostid, itemid, traffic):
	params = {"output":"extend", "itemids":itemid, "hostids":hostid, "time_from": six_ago, "time_till": local_timestamp}
	method = "history.get"
	get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
	traffic_out, traffic_in = [], []
        for i in get_content['result']:
		if 'in' in traffic:
			try:
				traffic_in.append(int(i['value']))
			except:
				traffic_in.append(0)
		else:
			try:
				traffic_out.append(int(i['value']))
			except:
				traffic_out.append(0)



	if 'in' in traffic:
		if len(traffic_in) != 360:
			for i in range(0,(360 - len(traffic_in))):
				traffic_in.append(0)
		return traffic_in
	else:
		if len(traffic_out) != 360:
                        for i in range(0,(360 - len(traffic_out))):
                                traffic_out.append(0)
		return traffic_out




'''整理数据并存储到数据库中'''
def save_db(a, groupid, g_groupid, data):
	all_out, all_in = [], []
        time_list = []

        for _time in range(six_ago, local_timestamp, 60):
                time_list.append(('%s0' %str(_time)[:9]))

        for d in data:
                if 'in' in d['key_']:
                        all_in += [ np.array(editor_history(a, d['hostid'], d['itemid'], d['key_'])[:360]) ]
                else:
                        all_out += [ np.array(editor_history(a, d['hostid'], d['itemid'], d['key_'])[:360]) ]

	sum_out, sum_in = list(sum(all_out)), list(sum(all_in))

	for i in range(0,360):
		sql = '''insert into traffic__summary (time, idc_hostgroupid, game_hostgroupid, out_value, in_value) values(%s, %s, %s, %s, %s)'''
		param = (time_list[i], groupid, g_groupid, sum_out[i], sum_in[i])
		cursor.execute(sql, param)




'''通过hostids获取网卡out/in的itemid'''
def editor_itemids(a, hostids, groupid):

        params = {"output":["hostid", "itemid", "key_"], "hostids":hostids, "search":{"key_":"net.if", "name":u"外网"}}
        method = "item.get"
        get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
        return get_content['result']



'''通过hostid找到其对应的游戏主机组'''
def editor_gamegroups(a, hostids, groupid):
        host_data = {}
	host_name = {}
        for hostid in hostids:
                params = {"output":["groupid", "name"], "hostids":hostid}
                method = "hostgroup.get"
                get_obj = get_json_obj(method,params)
                get_content = a.postRequest(get_obj)

                for i in get_content['result']:
                        if i['name'].split("_")[0] in [u'亚欧', u'韩国', u'港台']:
				host_name[i['groupid']] = i['name']
                                host_data[hostid] = i['groupid']
        d=defaultdict(list)
        for k,v in host_data.iteritems():
                d[v].append(k)
        for g_groupid, g_hostids in dict(d).items():
                data = editor_itemids(a, g_hostids, groupid)
		try:
	                save_db(a, groupid, g_groupid, data)
		except:
			pass



'''向flask返回数据'''
def return_datas(start_time, end_time, idc, game_list):
	total_data = {}
	for gameid in game_list.keys():
		sql = '''select in_value,out_value from traffic__summary where time between %s and %s and idc_hostgroupid = %s and game_hostgroupid = %s''' 
		param = (start_time, end_time, idc, gameid)
		cursor.execute(sql, param)
		total_data[gameid] = cursor.fetchall()
	return total_data






if __name__=="__main__":
	login = get_zabbix_login()
	a = zabbix_login(login[0], login[1], login[2])
	groups_hostids = editor_hosts(a, editor_hostgroup(a).keys())
	for groupid, hostids in groups_hostids.items():
		editor_gamegroups(a, hostids, groupid)
