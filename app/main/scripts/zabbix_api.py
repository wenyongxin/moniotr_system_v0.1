#!/usr/bin/env python
#ecoding:utf-8

import json, sys, urllib2
import locale
import re



class zabbix_API():

	def __init__(self, zabbix_user, zabbix_password, zabbix_server):
		self.zabbix_user = zabbix_user
		self.zabbix_password = zabbix_password
		self.zabbix_server = zabbix_server


	def login(self):
        	user_info = {'user':self.zabbix_user,'password':self.zabbix_password}
	        obj = {"jsonrpc":"2.0","method":'user.login',"params":user_info,"id":0}
        	json_obj = json.dumps(obj)
	        content = self.postRequest(json_obj)
        	return content['result']


	def postRequest(self, json_obj):
        	header = {'Content-Type':'application/json-rpc','User-Agent':'python/zabbix_api'}
		url = '%sapi_jsonrpc.php' % self.zabbix_server
        	request = urllib2.Request(url,json_obj,header)
	        result = urllib2.urlopen(request)
        	content = json.loads(result.read())
	        return content



def get_json_obj(method, params):
        get_obj = {"jsonrpc":"2.0","method":method,"params":params,"auth":auth,"id":1}
        return json.dumps(get_obj)


'''返回zabbix hostgroupid与name'''
def get_hostname(a):
	hostgroup_list = []
	params = {"output":["name","interfaces"]}
	method = "hostgroup.get"
	get_obj = get_json_obj(method,params)
	get_content = a.postRequest(get_obj)
	for info in get_content['result']:
		info_list = []
		info_list += [info['groupid'],info['name']]
		hostgroup_list.append(info_list)
	return hostgroup_list


'''zabbix根据IP地址返回对应的 host id'''
def get_hostid(a, ip):
	params = {"output":["hostid", "interfaces"],"selectInterfaces":["ip"], "filter":{"ip":ip} }
	method = "host.get"
	get_obj = get_json_obj(method,params)
	get_content = a.postRequest(get_obj)
	for i in  get_content['result']:
		return i['hostid']



'''根据hostid 更新主机信息。名称与主机组'''
def update_host(a, ip, hostid, name, groupids):
	params = {"hostid" : hostid,
		"name" : ('%s_%s' %(name, ip)),
		"groups" : groupids
		}
	method = "host.update"
	get_obj = get_json_obj(method,params)
	get_content = a.postRequest(get_obj)
	print get_content


'''创建主机组'''
def create_hostgroup(a, group_name):
	params = {"name":group_name}
	method = "hostgroup.create"
	get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
	return get_content['result']['groupids'][0]
	
	
'''zabbix登录生成auth id号'''
def zabbix_login(zabbix_server, zabbix_user, zabbix_password):
	global auth
	a = zabbix_API(zabbix_user, zabbix_password, zabbix_server)
	auth = a.login()
	return a

''' ----------------- 更新日期 2016-7-3 ----------------- '''

'''获取执行扫描用户名称'''
def get_user(a):
	scan_user = []
	total = {}
	params = {"output":["alias","userid"]}
        method = "user.get"
        get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
        for i in get_content['result']:
		total[i['alias']] = i['userid']
                if u"测试_"  in i['alias']:
			scan_user.append((i['alias']).split('_')[1])
	return (scan_user,total)

'''模拟用户登录zabbix并获取hostgroup信息'''
def get_hostname(a):
	hostgroup_dic = {}
	params = {"output":["groupid", "name"]}
	method = "hostgroup.get"
        get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
        for i in get_content['result']:
		hostgroup_dic[i['groupid']] = i['name']
	return hostgroup_dic


'''通过hostgroupid获取对应的ip'''
def get_hostip(a, groupid):
        hosts_dic = [] 
	names_dict = {}
        params = {"output":["groupid", "hosts"],"selectHosts":["hostid", "name"] , "filter":{"groupid":groupid}}
        method = "hostgroup.get"
        get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
        for i in get_content['result']:
		for hostid in i['hosts']:
			hosts_dic.append(hostid['hostid'])
			names_dict[hostid['hostid']] = hostid['name']
	return (hosts_dic, names_dict)

'''通过hostid获取对应的IP地址, 上面的函数可以获取到host的IP地址，但是相对来说不准，所以再通过以下方式获取IP地址'''
def get_host(a, hostids):
	hostips = {}
	params = {"output":"extend", "hostids":hostids}
	method = "hostinterface.get"
        get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
        for i in get_content['result']:
		if i['hostid'] != []:
			hostips[i['hostid']] = i['ip']
	return hostips
		

''' ----------------- 更新日期 2016-7-18 ----------------- '''

'''从usergroup中获取用户名称'''
def get_groupusers(a):
        users = []
        params = {"output":["usrgrpid","name"]}
        method = "usergroup.get"
        get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
        for i in get_content['result']:
		if "User_" in i['name']:
			users += i['name'].split(u"（")[0].split("_")[-1].split('&')
	newusers = list(set(users))
	newusers.sort(key=locale.strxfrm)
	return newusers




'''-------------- 更新日期 2016-8-30 -----------------'''
'''通过idc获取下面的所有游戏组名称'''
def get_gamename(a, idc):
	idc_hostids = {}
	params = {"selectGroups":["groupid","name"], "groupid":idc}
	method = "host.get"
	get_obj = get_json_obj(method,params)
	get_content = a.postRequest(get_obj)
	for a in get_content['result']:
		dicts = {}
		if len(a['groups']) > 1:
			for b in a['groups']:
				dicts[b['groupid']] = b['name']
		if dicts.has_key(str(idc)):
			dicts.pop(str(idc))
			for k,v in dicts.items():
				if v.split("_")[0] in [u"亚欧", u"港台", u"韩国"]:
					idc_hostids[k] = v
	return idc_hostids 

'''通过用户名获取对应的手机号码'''
def get_user_phone(a, name):
	params = {"output":["userid","surname","alias"]}
	method = "user.get"
	get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
	new_dict = {}
	for a in get_content['result']:
		if a['surname'].split(":")[-1]:
			new_dict[a['alias']] = a['surname'].split(":")[-1]
	return new_dict[name]


'''------------- 更新日期 2016年-9-6 ------------------'''
def return_rights(hostgroupids):
	rights = []
        for hostgroupid in hostgroupids:
                rights += [{"permission": 2, "id": str(hostgroupid)}]
	return rights
	


'''获取usergroup的id号用于判断是否存在'''
def get_usergroup(a, name):
	params = {"output": ["usrgrpid","name"], "filter":{"name":name}}
        method = "usergroup.get"
        get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
	return get_content['result']


'''创建usergroup组'''
''' name 对应登录用户名  bear 对应第几负责人'''
def create_usergroup(a, name, hostgroupids, userid):
	params = {"name": name, "rights": return_rights(hostgroupids), "userids": userid}
        method = "usergroup.create"
        get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
	return get_content


'''当主机组创建完毕后，就需要做update更新权限'''
def update_usergroup(a, usrgrpids, hostgroupids):
	params = {"usrgrpids": usrgrpids, "rights": return_rights(hostgroupids)} 
	method = "usergroup.massupdate"
	get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
        return get_content


def usergroup_main(a, head, hostgroupids, username):
	name = u"User_%s（%s）" %(username, head)
	n = get_usergroup(a, name)
	if len(n) == 0:
		userid = get_user(a)[1][username]
		create_usergroup(a, name, hostgroupids, userid)
	else:
		update_usergroup(a, n[0]['usrgrpid'], hostgroupids)		

'''----------------- 更新日期 2016-9-7 -----------------'''
'''通过hostname返回对应的hostid值'''
def get_hostnameid(a, hostname):
	params = {"output":["groupid", "name"], "filter":{"name":hostname}}
        method = "hostgroup.get"
        get_obj = get_json_obj(method,params)
        get_content = a.postRequest(get_obj)
	return int(get_content['result'][0]['groupid'])
	


if __name__=="__main__":
	zabbix_server = 'http://zabbix.efuntw.com/'
	#zabbix_server = 'http://172.16.5.240/zabbix/' 
	zabbix_user = 'admin'
	zabbix_password = 'zabbix'
	a = zabbix_login(zabbix_server, zabbix_user, zabbix_password)
#	hostgroupids = [ 11,10]
#	username = u'陈政'
#	head = u'一负'
#	usergroup_main(a, head, hostgroupids, username)
	#hostname = u'L_六龙御天_远传_繁'
	#get_hostnameid(a, hostname)
	print get_user(a)[1]
