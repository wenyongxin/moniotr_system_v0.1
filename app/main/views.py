#ecoding:utf-8
from flask import Flask, render_template, session, redirect, url_for, flash, abort
from flask.ext.login import login_user, logout_user, login_required, current_user
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, AddMachineForm, CheckMachineForm, systems, InsertZabbixInfo
from .. import db
from ..models import User, Role, Machine, ReportDns, ZabbixInfo, SpecialPort, ScanGroup, ReportFault, FaultOperationsCenter, FaultType, FaultAttribution, ReportFileInfo, MonitorFile, ManagerDns, OpenVAS, En_To_Cn, Traffic_Summary, Ssh_History, Game_Distribution
from flask.ext.login import login_user, logout_user, login_required, current_user
from ..decorators import admin_required, permissions
from werkzeug.utils import secure_filename # 获取一个安全的文件名，且仅仅支持ascii字
from ..email import send_email

import sys, os, datetime, time, json
import xlrd #excel 文件读取 
import calendar # 用于日期范围的计算
import collections #用户做列表计算
import locale #用于汉字的排序 
import re
import whois
from collections import Counter

#用paramiko 连接
import paramiko, pickle 


reload(sys)
sys.setdefaultencoding( "utf-8" )

colors = ["#2D6B96", "#327AAD", '#3E90C9', '#55A7E3', '#60B6F0', '#81C4F0', '#9CCEF0', "#00BFFF", "#ADD8E6", "#B0E0E6", "#5F9EA0", "#F0FFFF", "#E0FFFF", "#AFEEEE", "#00FFFF", "#00FFFF", "#00CED1", "#2F4F4F"]

def change_stamp(date):
	try:
		timeArray = time.strptime(date, "%Y-%m-%d")
	except:
		timeArray = time.strptime(date, "%Y-%m-%d %H:%M:%S")
	return  int(time.mktime(timeArray))



@main.route('/', methods=['GET', 'POST'])
@login_required
def index():
	'''当前月份的故障类型'''
	day_now = time.strftime('%Y-%m-%d',time.localtime(time.time())) 
	'''月初日期'''
	day_begin = day_now[0:8]+'01'
	'''月日期范围'''
	monthRange = calendar.monthrange(int(day_now[0:3]),int(day_now[5:7]))
	'''月尾日期'''
	day_end = day_now[0:8]+str(monthRange[1])

	fault_all = ReportFault.query.filter_by(fault_month = day_now[0:7]).all() 
	'''统计故障类型'''
	fault_type_list = []
	for faule in fault_all:
		fault_type_list.append(faule.fault_type)
	
	ftypeslist = []
	for key,value in dict(collections.Counter(fault_type_list)).items():
		absolutely = int((float(value) / float(len(fault_type_list))) * 100)
		ftypeslist += [[ key.encode('utf-8'), absolutely ]]


	'''季度运营中心故障数量'''
	Months = []
	The_Mo = int(day_now[5:7])
	for Mon in range(The_Mo - 3, The_Mo + 1):
		if Mon > 9:
			Months.append(('%s-%s' %(day_now[0:4], Mon)))
		else:
			Months.append(('%s-0%s' %(day_now[0:4], Mon)))
	
	
	month_centers = {}
	for m in Months:
		sing_centers = []
		for request in ReportFault.query.filter_by(fault_month = m).all():
			if request.fault_operations_center != u'技术中心':
				sing_centers.append(request.fault_operations_center)
		month_centers[m] = dict(collections.Counter(sing_centers))
	
	'''整理渲染数据格式'''	
	center_datas = []
	for center in FaultOperationsCenter.query.all():
		if center.fcenter != u'技术中心':
			num = [center.fcenter.encode('utf-8')]
			for mon in Months:
				value = month_centers.get(mon)
				num.append(value.get(center.fcenter,0))
			center_datas.append(num)


	'''月份运营中心故障类型占比数据统计'''
	problems = []
	for center in FaultOperationsCenter.query.all():
		if center.fcenter != u'技术中心':
			for ftype in FaultType.query.all():
				for fault_info in ReportFault.query.filter_by(fault_operations_center = center.fcenter, fault_type = ftype.ftype).all():
					str_problem = u'%s-%s' %(center.fcenter, ftype.ftype)
					problems.append(str_problem)
	centers_types = []
	for center in FaultOperationsCenter.query.all():
                if center.fcenter != u'技术中心':
			for key,value in  dict(collections.Counter(problems)).items():
				if center.fcenter == key.split('-')[0]:
					absolutely = int((float(value) / float(len(problems))) * 100)
					centers_types += [[ key.encode('utf-8'), absolutely ]]

	'''用于统计每天故障报告的数量'''
	day_faults = []
	for stamp in range(change_stamp(day_begin), change_stamp(day_end) + 86400, 86400):
		dtime = time.strftime('%Y-%m-%d',time.localtime(stamp))
		report = ReportFault.query.filter_by(fault_date = dtime).all()
		if report:
			day_faults += [[ dtime, len(report) ]]
		

		

	


	return render_template('index.html', type_list = json.dumps(ftypeslist), type_colors = colors[:len(ftypeslist)], Month = day_now[0:7], day_begin = day_begin, day_end = day_end,
				center_datas = json.dumps(center_datas), Months = Months, centers_types = json.dumps(centers_types), center_type_color = colors[:len(centers_types)], day_faults = json.dumps(day_faults))

@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    return render_template('user.html', user=user)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash(u'你的信息已更新')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@main.route('/edit-profile/<int:id>', methods=['GET','POST'])
@login_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    print type([(role.id, role.name) for role in Role.query.order_by(Role.name).all()])
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash(u'配置文件已更新')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)

import re,os,urllib,pickle, json
from threading import Thread
from scripts.par_pass import par_pass_main
from scripts.check_pc import check_pc_main
#from scripts.zabbix_api import zabbix_login, get_hostname, update_host, get_hostid, create_hostgroup, get_user, get_hostname, get_hostip, get_host, get_groupusers, get_gamename, get_user_phone, get_hostnameid
from scripts.zabbix_api import * 
from flask import request 
from scripts.port_scan import scan_main

from scripts.to_excel import mkdir_file, mkdir_worksheet, mkdir_excel, close_file, refule_report
from scripts.game_scan import Thread_Ip
from scripts.conn_openvas import Thread_openvas
from scripts.traffic_summary import return_datas

reip = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
pick_path = os.getcwd()

@main.route('/addmachine-2', methods=['GET','POST'])
@login_required
def add_machine_2():
	machines = Machine.query.all()
	form = AddMachineForm() # 包含 端口号 port  密码 password
	form2 = CheckMachineForm() # 包含 ip 系统 system proxy地址
	if form.validate_on_submit():
	        ips = reip.findall(form2.ip.data)
		port = int(form.port.data)
		password = form.password.data
		proxy = form2.proxy.data
		system = form2.system.data
	        for ip in ips:
			mac = Machine.query.filter_by( ip = ip ).first()
			machine = Machine(ip=ip, port=port, proxy=proxy, system=system, password=password, i_user=current_user.username)
			if mac: 
        	                db.session.delete(mac)
			else:
				db.session.add(machine)
			db.session.add(machine)

			db.session.commit()

		filename = MonitorFile.query.order_by('id desc').all()[0].file_name
	        par_pass_main( ips, password, port, filename, system, proxy)

        	info = {}
		ipss = []
		for ip in ips:
			mac = Machine.query.filter_by( ip = ip ).first()
			try:
				info[ip] = json.loads(mac.data)
				ipss.append(ip)
				flash(u'监控添加完毕')
			except StandardError,e:
				flash((u'添加异常%s' %e))
		return render_template('addmachine2.html', form=form, form2=form2, ips=ipss, info=info)
	return render_template('addmachine2.html', form=form, form2=form2)

from scripts.check_pc import check_port,check_pass


@main.route('/addmachine-2/check', methods=['GET','POST'])
@login_required
def check_pc():
	machines = Machine.query.all()
	form = CheckMachineForm()
	password_list = ['Efun@168']
	port_list = [36000]
	if form.validate_on_submit():
		for a in machines:
			password_list.append(a.password)
			port_list.append(int(a.port))

		proxy = form.proxy.data
		system = form.system.data
		passwords = list(set(password_list))
		ports = list(set(port_list))
		ips = reip.findall(form.ip.data)


		try:
			info_dict = check_pc_main(ips, ports, passwords, proxy, system )
			print info_dict
		except:
			flash(u'未找到信息，请手动添加监控')


		if info_dict:
			filename = MonitorFile.query.order_by('id desc').all()[0].file_name
			Threads = []
			for ip in info_dict.keys():
				value = info_dict[ip]
				mac = Machine.query.filter_by( ip = ip ).first()
				machine = Machine(ip=ip, port=value[0], proxy=value[2], system=value[3], password=value[1], i_user=current_user.username)
				if mac: 
					db.session.delete(mac)
				else:
					db.session.add(machine)
				db.session.add(machine)
				db.session.commit()

				Threads.append(Thread( target = par_pass_main, args = (ip, value[1], value[0], filename, value[3], value[2], 1)))

			for thread_object in Threads:
				thread_object.start()

			for thread_object in Threads:
				thread_object.join()

			info = {}
			for ip in info_dict.keys():
				print ip
				mac = Machine.query.filter_by( ip = ip ).first()
				try:
					info[ip] = json.loads(mac.data)
				except:
					print e
			print info
			flash(u'监控添加完毕')
		else:
			flash(u'匹配异常')
		return render_template('checkpc.html', form=form, ips=ips, info=info)
	return render_template('checkpc.html', form=form)	



def change_name(info):
	info_dict = {}
	for b in info:
		info_dict[b[0]] = b[1]
	return info_dict


@main.route('/monitor_host', methods=['GET','POST'])
@login_required
def monitor_host():
	name = u"监控安装"
	machines = Machine.query.order_by('id desc').all() # 数据库进行倒叙排列，order_by('id desc') 用于指定以id值排序
	if len(machines) == 0:
		len_page = [machines]
	else:
		len_page = [machines[i:i + 20] for i in range(0, len(machines), 20)]

	page = int(request.args.get('page',''))
	url = 'http://monitor.efuntw.com:4200/' 
	return render_template('monitor_host.html', name=name, machines=len_page[page - 1], system_dict=change_name(systems), total_page = len_page, all_page = len(len_page), url = url)


@main.route('/monitor_host/change', methods=['GET'])
@login_required
def monitor_change():
	zabbix_info = ZabbixInfo.query.all()[0]
	a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)
	list_info = get_hostname(a)
	list_info = sorted(get_hostname(a).iteritems(), key=lambda d:d[1], reverse = True)

	ids = request.args.get('ids','').split(',')
	data = []
	for oid in ids:
		data.append(Machine.query.filter_by(id = oid).first().ip)
	return render_template('change.html', ips=' '.join(data), list_info=list_info)
	



@main.route('/monitor_host/change/info', methods=['GET','POST'])
@login_required
def change_host():
	ips= reip.findall(request.args.get('host',''))
	name = request.args.get('name','')
	groupids = request.args.get('second','').split(',')
	new_hostgroup = request.args.get('new_hostgroup','')
	zabbix_info = ZabbixInfo.query.all()[0]
	a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)
	if new_hostgroup != "":
		groupids.append(create_hostgroup(a, new_hostgroup))

	for oip in ips:
		hostid = get_hostid(a, oip)
		update_host(a, oip, hostid, name, groupids)
		mon = Machine.query.filter_by(ip=oip).first()
		mon.monitor = '1'
		db.session.add(mon)
		db.session.commit()	

	flash((u'%s 已经更新' % (' '.join(ips))))
	return redirect(('%s?page=1' %url_for('main.monitor_host')))

@main.route('/monitor_host/ssh', methods=['GET','POST'])
@login_required
def ssh_host():
	data = json.loads(request.get_data())

	mon = Machine.query.filter_by(id = data['id']).first()	
	info = {'ipaddr': mon.ip, 'password': mon.password, 'port': mon.port, 'login_user': current_user.username}
	with file('/tmp/ssh.pkl','wb') as f:
		pickle.dump(info,f)
	return redirect(('%s?page=%s' %(url_for('main.monitor_host'), data['page'])))




@main.route('/monitor_host/history', methods=['GET','POST'])
@login_required
def ssh_history():
	login_user = []
	history = Ssh_History.query.order_by('id desc').all()
	for h in history:
		login_user.append(h.user)
	
	name = u"命令历史记录"
	return render_template('monitor_history.html', name=name, history=history[:30], login_user = list(set(login_user)))
	



@main.route('/config', methods=['GET','POST'])
@login_required
def config():
	form = InsertZabbixInfo()
	name = u"配置信息"
	manager_user = User.query.all()

	'''zabbix管理'''
	zabbix_type = ['formal','text']
	zabbix_total = {}
	for ztype in zabbix_type:
		zabbix = ZabbixInfo.query.filter_by( zabbix_info = ztype ).first()
		zabbix_total[ztype] = zabbix
	
	if request.method == "POST":
		data = json.loads(request.get_data())

		if data.has_key('password'):
			change_password = User.query.filter_by( id = data['id'] ).first()
			change_password.password = data['password']
			change_password.password_hash
			db.session.add(change_password)
		        db.session.commit()

		elif data.has_key('name'):
			change_profile = User.query.filter_by( id = data['id'] ).first()
			change_profile.name = data['name']
			change_profile.location = data['location']
			change_profile.about_me = data['about']
			db.session.add(change_profile)
			db.session.commit()
		elif data.has_key('perm'):
			user = User(email=data['email'], username=data['username'], password=data['passwd'], confirmed=1, role_permissions = data['perm'])
			db.session.add(user)
			db.session.commit()
			token = user.generate_confirmation_token()
			send_email(user.email, u'您的用户以创建','auth/email/confirm', user=user, token=token)
	
		else:
			try:
				a = zabbix_login(data.values()[0][0], data.values()[0][1], data.values()[0][2])
				if len(ZabbixInfo.query.filter_by(zabbix_info = data.keys()).all()) == 1:
					if data.keys() == "formal":
						zabbix = ZabbixInfo.query.filter_by(zabbix_info = data.keys()).first()
						zabbix.zabbix_server = data['formal'][0]
						zabbix.zabbix_user = data['formal'][1]
						zabbix.zabbix_password = data['formal'][2]
						zabbix.zabbix_info = "formal"
					else:
						zabbix = ZabbixInfo.query.filter_by(zabbix_info = data.keys()).first()
						zabbix.zabbix_server = data['text'][0]
	                        	        zabbix.zabbix_user = data['text'][1]
        	                        	zabbix.zabbix_password = data['text'][2]
	                	                zabbix.zabbix_info = "text"
					db.session.add(zabbix)
				else:
					if data.keys() == "formal":
						zabbix = ZabbixInfo(zabbix_server = data['formal'][0], zabbix_user = data['formal'][1], zabbix_password = data['formal'][2], zabbix_info = "formal")	
					else:
						zabbix = ZabbixInfo(zabbix_server = data['text'][0], zabbix_user = data['text'][1], zabbix_password = data['text'][2], zabbix_info = "text")	
					db.session.add(zabbix)
					flash(u'更新成功')
				return redirect(url_for('main.config'))
			except:
				flash(u'验证错误')
				return redirect(url_for('main.config'))
	else:
		id = request.args.get('id','')
		if id:
			del_user = User.query.filter_by( id = id ).first()
			db.session.delete(del_user)
			db.session.commit()   
			return redirect(url_for('main.config'))

		permissions = request.args.get('permissions','')
		if permissions:
			user_id = request.args.get('user','')
			update_user = User.query.filter_by( id = user_id ).first()
			update_user.role_permissions = permissions
			db.session.add(update_user)
			db.session.commit()
                        return redirect(url_for('main.config'))

		
	return render_template('config.html', name=name,zabbix_total = zabbix_total, manager_user = manager_user)



@main.route('/report', methods=['GET','POST'])
@login_required
def report_dns():
	name = u"DNS记录"

	'''统计当前数据库中所存放的域名'''
	domains = []
	for domain in ReportDns.query.all():
		domains.append(domain.domain_name)
	if len(domains) == 0:
		domains = [u'无数据']
	

	'''接收前段页面post数据，并转换存入到数据库中'''
	if request.method == "POST":
		datas = request.get_data()
		for data in json.loads(datas):
			if data[0] != "None":
				report_dns = ReportDns(domain = ('%s.%s' %(data[0].strip(), data[2].strip())), 
							domain_name = data[2].strip(), domain_type = data[1].strip(), 
							domain_add = data[3].strip(), operation = current_user.username, 
							game_name = data[4].strip(), game_lange = data[5].strip(), game_static = 0)      
		                db.session.add(report_dns)
		return redirect(url_for('main.report_dns'))
	else:
		'''前端页面get请求，返回查询的结果'''
		page = request.args.get('page','')
		wd = request.args.get('wd','')
		if request.args.get('filename',''):
			filename = request.args.get('filename','')
		else:
			filename = "None"
		if wd:
			if ReportDns.query.filter_by( domain = wd ).all():
				dns_all = ReportDns.query.filter_by( domain = wd ).all()

			elif ReportDns.query.filter_by( domain_add = wd ).all():
				dns_all = ReportDns.query.filter_by( domain_add = wd ).all()

			elif ReportDns.query.filter_by( game_name = wd ).all():
				dns_all = ReportDns.query.filter_by( game_name = wd ).all()

			else:
				dns_all = ReportDns.query.all()
				flash((u'没找到: %s' %wd))
				return redirect(url_for('main.report_dns'))


			len_page = [dns_all]
			try:
				all_dns = {u'查询结果' : len_page[int(page) - 1 ]}
			except:
				all_dns = {u'查询结果' : len_page[0]}
			all_page = {u'查询结果' : len_page }
			page_num = {u'查询结果' : len(len_page)}
			dns_num = False 
			efundomain = request.args.get('efundomain',u'查询结果')
		else:
			'''默认前端页面的请求完成数据的整理以及分页的功能'''
			all_dns, all_page, page_num, dns_num = {}, {}, {}, {}
			for dom in list(set(domains)):
				dns_all = ReportDns.query.filter_by( domain_name = dom ).all()
				if len(dns_all) == 0:
					len_page = [dns_all]
				else:
					len_page = [dns_all[i:i + 15] for i in range(0, len(dns_all), 15)]
				try:
					all_dns[dom] = len_page[int(page) - 1 ]
				except:
					all_dns[dom] = len_page[0]

				all_page[dom] = len_page
				page_num[dom] = len(len_page)
				dns_num[dom] = len(dns_all)
			efundomain = request.args.get('efundomain',list(set(domains))[0])

		if request.args.get('delete',''):
			id = request.args.get('delete','')
			dns_id = ReportDns.query.filter_by( id = id ).first()
			db.session.delete(dns_id)
			db.session.commit()   
			return redirect(("%s?efundomain=%s&page=1" %(url_for('main.report_dns'), dns_id.domain_name)))


		'''通过zabbixAPI接口获取hostgroup名称'''
		zabbix_info = ZabbixInfo.query.all()[0]
	        a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)
        	list_info = get_hostname(a)
	        list_info = sorted(get_hostname(a).iteritems(), key=lambda d:d[1], reverse = True)

	return render_template('report_dns.html', name=name, all_dns=all_dns, all_page = all_page, page_num = page_num, defdomain = efundomain, domains=ManagerDns.query.order_by('id desc').all(), list_info=list_info, filename=filename, dns_num=dns_num)

'''保存上传的excel文件'''
@main.route('/updatefile', methods=['GET','POST'])
@login_required
def update_file():
	filepath = r'%s/app/static/update/' % pick_path
	if request.method == "POST":
		file = request.files['file']
		if file:
			filename = secure_filename(file.filename)
			file.save(os.path.join(filepath, filename))
			data = xlrd.open_workbook(os.path.join(filepath, filename))
			for num in range(0, int(data.nsheets)):
				table = data.sheets()[num]
				for i in range(table.nrows):
					datas = table.row_values(i)
					report_dns = ReportDns(domain = datas[0], domain_name = '.'.join(datas[0].split('.')[-2:]), 
								domain_type = datas[1], domain_add = datas[2], 
								operation = datas[5], game_name = datas[3], game_lange = datas[4])
					db.session.add(report_dns)
			flash(u'已更新')
			return redirect(url_for('main.report_dns'))
		else:
			flash(u'请选择文件')
			return redirect(url_for('main.report_dns'))



'''用于做excel导出功能'''
@main.route('/dns/toexcel', methods=['GET','POST'])
@login_required
def report_dns_toexcel():
	title = [u'游戏域名', u'解析类型', u'地址', u'游戏名称', u'用途', u'操作人']

	domains = []
	for domain in ReportDns.query.all():
		domains.append(domain.domain_name)

	all_dns = {}
	for dom in list(set(domains)):
		dns_all = ReportDns.query.filter_by( domain_name = dom ).all()
		domain_dict = []
		for a in dns_all:
			domain_dict += [[ a.domain, a.domain_type, a.domain_add, a.game_name, a.game_lange, a.operation ]]

		all_dns[dom] = domain_dict


	filename = "report_dns_%s.xlsx" % time.strftime("%Y-%m-%d")
	filepath = r'%s/app/static/files/%s' %(pick_path, filename)
	workbook = mkdir_file(filepath)

	for dns, value in all_dns.items():
		worksheet = mkdir_worksheet(workbook, dns)
		mkdir_excel(workbook, worksheet, value, title, special_port = False)
	close_file(workbook)
	save_file_info = ReportFileInfo(operation_user = current_user.username, file_form = u'DNS报告', file_name = filename )
	db.session.add(save_file_info)
	return redirect('%s?page=1&filename=%s' % (url_for('main.report_dns'), filename))
	




@main.route('/fault', methods=["GET","POST"])
@login_required
def report_fault():
	global title
	name = u"故障报告"
	title = [u'日期','故障描述',u'影响范围',u'影响时长(分钟)',u'是否影响用户体验',u'影响用户',u'直接经济损失（美元）',u'数据来源',u'是否核心服务',u'业务模块',u'运营中心',u'故障类型',u'处理负责人',u'归属',u'状态',u'故障原因与处理',u'教训总结',u'改进']

	'''用于获取到时间范围'''
	SelectStart = request.args.get('SelectStart','')
	SelectEnd = request.args.get('SelectEnd','')
	page = request.args.get('page','')
	if request.args.get('filename',''):
		filename = request.args.get('filename','')
	else:
		filename = "None"



	if SelectStart:
		fault_all = []
		for stamp in range(change_stamp(SelectStart), change_stamp(SelectEnd) + 86400, 86400):
			dtime = time.strftime('%Y-%m-%d',time.localtime(stamp))
			report = ReportFault.query.filter_by(fault_date = dtime).all()
			if report:
				fault_all+= report
		fault = fault_all
		len_page = [[fault_all]]
		if fault_all == []:
			fault_all = [[]]
			flash(u'没有找到数据请重试')
	else:
		fault_all = ReportFault.query.order_by('id desc').all()
		len_page = [fault_all[i:i + 5] for i in range(0, len(fault_all), 5)]
		try:	
			fault = len_page[int(page) - 1]
		except:
			if len(fault_all) == 0:
				fault = fault_all
			else:
				fault = fault_all[0] 

	fcenter = FaultOperationsCenter.query.all()
	ftype = FaultType.query.all()
	fattribution = FaultAttribution.query.all()


	'''前段页面报表功能'''	
	fault_type = []
	fault_center = []
	fault_core = []

	core_impact_time = []
	uncore_impact_time = []
	for a in fault_all:
		try:
			fault_type.append(a.fault_type)
			if a.fault_operations_center != u"技术中心":
				fault_center.append(a.fault_operations_center)
			
			if a.fault_core_business:
				core_impact_time.append(int(a.fault_impact_time))
				
			else:
				uncore_impact_time.append(int(a.fault_impact_time))

		except:
			pass
	cores_data = {}
	cores_data['core'] = ['%.2f' % float((1 - float(sum(core_impact_time)) / 10080) * 100), sum(core_impact_time)]
	cores_data['uncore'] = ['%.2f' % float((1 - float(sum(uncore_impact_time)) / 10080) * 100), sum(uncore_impact_time)]
	if len(cores_data):
		cores_data = {'core': [0, 0], 'uncore': [0, 0]}	

	fau = dict(collections.Counter(fault_type))
	cen = dict(collections.Counter(fault_center))
	ftypestr = []
	for k,v in fau.items():
		absolutely = int((float(v) / float(len(fault_type))) * 100)
		ftypestr += [[k.encode('utf-8'),absolutely]]

	fcenterstr = []
	for k,v in cen.items():
		fcenterstr += [[ k.encode('utf-8'),v]]	
	

		
	'''针对utf-8进行排序'''
	zabbix_info = ZabbixInfo.query.all()[0]
	a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)
	list_info = get_hostname(a).values()
	list_info.sort(key=locale.strxfrm)

	'''用于能在页面根据运营中心而区分对应的游戏'''	
	tw,ae,kr,cn,it = [],[],[],[],[]
	new_center_dict = {}
	for group in list_info:
		if u"港台_" in group:
			tw.append(group)
		elif u"亚欧_" in group:
			ae.append(group)
		elif u"韩国_" in group:
			kr.append(group)
		elif u"国内_" in group:
			cn.append(group)
		elif u"p_平台":
			it.append(group)
	new_center_dict['tw'], new_center_dict['ae'], new_center_dict['kr'], new_center_dict['cn'], new_center_dict['it'] = tw, ae, kr, cn, it
	


	'''用于做th中故障类型、运营中心、归属的数据库操作'''
	if request.get_data(): 
		obj = json.loads(request.get_data())
		try:
			if obj.keys()[0].split('_')[0] == 'del':
				if obj.keys()[0].split('_')[1] == 'type':
					deldata = FaultType.query.filter_by(id = obj.values()[0]).first()
				if obj.keys()[0].split('_')[1] == 'center':
					deldata = FaultOperationsCenter.query.filter_by(id = obj.values()[0]).first()
				if obj.keys()[0].split('_')[1] == 'attribution':
					deldata = FaultAttribution.query.filter_by(id = obj.values()[0]).first()
				db.session.delete(deldata)
			elif obj.keys()[0].split('_')[0] == 'add':
				if obj.keys()[0].split('_')[1] == 'type':
					adddata = FaultType(ftype=obj.values()[0])
				if obj.keys()[0].split('_')[1] == 'center':
					adddata = FaultOperationsCenter(fcenter=obj.values()[0])
				if obj.keys()[0].split('_')[1] == 'attribution':
					adddata = FaultAttribution(fattribution=obj.values()[0])
				db.session.add(adddata)
			db.session.commit() 
		except:
			pass
			


	return render_template('report_fault.html', name=name, title=title, fault=fault, fcenter=fcenter, ftype=ftype, fattribution=fattribution, total_data=len_page, all_page = len(len_page),cores_data = cores_data, 
				fault_type = json.dumps(ftypestr), type_colors=colors[:len(ftypestr)], fault_center = json.dumps(fcenterstr), center_colors = colors[:len(fcenterstr)], 
				list_info=list_info, new_center_dict=new_center_dict, users = get_groupusers(a), filename=filename)



'''用于故障报告存储成excel'''
@main.route('/fault/toexcel', methods=["GET","POST"])
@login_required
def report_fault_toexcel():
	ids = request.args.get('ids','').split(',')
	cos, uncos, datas = [], [], []
	for id in ids:
		report = ReportFault.query.filter_by(id = id).first()
		if report:
			a = report.fault_date
			t = time.strftime("%Y-%m-%d", a.timetuple())
			if report.fault_user_experience:
				fault_user_experience = u"是"
			else:
				fault_user_experience = u"否"	
	
			if report.fault_core_business:
				fault_core_business = u"是"
			else:
				fault_core_business = u"否"
	
			if report.fault_status:
				fault_status = "完成"
			else:
				fault_status = "跟进"

			if report.fault_clusion == "None":
				fault_clusion = ""
			else:
				fault_clusion = report.fault_clusion

			if report.fault_improve == "None":
				fault_improve = ""
			else:
				fault_improve = report.fault_improve

			if report.fault_core_business:
				cos.append(int(report.fault_impact_time))
			else:
				uncos.append(int(report.fault_impact_time))
		
		datas += [[t, report.fault_describe, report.fault_range, report.fault_impact_time, fault_user_experience, report.fault_affect_user, report.fault_economic_losses, report.fault_data_form,
			fault_core_business, report.fault_business_module, report.fault_operations_center, report.fault_type, report.fault_head, report.fault_attribution, fault_status, report.fault_cause_problem, 
			fault_clusion, fault_improve]]
	heads = [sum(cos), '%.2f' % float((1 - float(sum(cos)) / 10080) * 100), sum(uncos), '%.2f' % float((1 - float(sum(uncos)) / 10080) * 100)]
	filename = "report_fault_%s.xlsx" % time.strftime("%Y-%m-%d") 
	filepath = r'%s/app/static/files/%s' %(pick_path, filename)
	workbook = mkdir_file(filepath)
	worksheet = mkdir_worksheet(workbook)
	refule_report(workbook, worksheet, title, datas, heads)
	monthfault = request.args.get('monthfault','')
	if monthfault == "1":
		'''用于调用生成月度总结报告'''
		pass
	else:
		close_file(workbook)
		save_file_info = ReportFileInfo(operation_user = current_user.username, file_form = u'故障报告', file_name = filename )
	        db.session.add(save_file_info)
	return redirect('%s?page=1&filename=%s' % (url_for('main.report_fault'), filename))




'''用于做数据库更新'''
@main.route('/fault/update', methods=["GET","POST"])
@login_required
def report_fault_update():
	datas = json.loads(request.get_data())
	for id,value in datas.items():
		report = ReportFault.query.filter_by(id = id).first()
		report.fault_date = value[0]
		report.fault_describe = value[1]
		report.fault_range = value[2]
		report.fault_impact_time = value[3]
		report.fault_user_experience = value[4]
		report.fault_affect_user = value[5]
		report.fault_economic_losses = value[6]
		report.fault_data_form = value[7]
		report.fault_core_business = value[8]
		report.fault_business_module = value[9]
		report.fault_operations_center = value[10]
		report.fault_type = value[11]
		report.fault_head = value[12]
		report.fault_attribution = value[13]
		report.fault_status = value[14]
		report.fault_cause_problem = value[15]
		report.fault_clusion = value[16]
		report.fault_improve = value[17]
		report.fault_app_type = value[18]
		db.session.add(report)  
		db.session.commit()   


'''用于做数据库保存'''
@main.route('/fault/save', methods=["GET","POST"])
@login_required
def report_fault_save():
	value = json.loads(request.get_data())
	report = ReportFault(fault_date = value[0],
				fault_describe = value[6],
				fault_range = value[7],
				fault_impact_time = value[1],
				fault_user_experience = value[2],
				fault_affect_user = value[3],
				fault_economic_losses = value[4],
				fault_data_form = value[5],
				fault_core_business = value[8],
				fault_operations_center = value[10],
				fault_business_module = value[9],
				fault_type = value[11],
				fault_head = value[12],
				fault_attribution = value[15],
				fault_status = value[16],
           	                fault_cause_problem = value[13],
				fault_clusion = value[14],
				fault_improve = value[17],
				fault_app_type = value[18],
				fault_month = value[0][0:7]
                        )
	db.session.add(report)
	db.session.commit()

'''用于删除对应的数据'''
@main.route('/fault/del', methods=["GET","POST"])
@login_required
def report_fault_del():
	ids = request.args.get('ids','')
	for id in ids.split(','):
		report = ReportFault.query.filter_by(id = id).first()
		db.session.delete(report)
		db.session.commit()
	return redirect(('%s?page=1' % url_for('main.report_fault')))
		

'''用于保存特殊端口的'''
@main.route('/nmap/save', methods=['GET','POST'])
@login_required
def save_port():
	ports = request.args.get("ports", "").split(',')
	for port in ports:
		save_port = SpecialPort(port=port)
		db.session.add(save_port)
	page = request.args.get("page", "")
	return redirect('%s?user=All' %url_for('main.game_nmap'))
	


'''用于删除特殊端口的'''
@main.route('/nmap/del/<id_num>', methods=['GET','POST'])
@login_required
def delete_nmap(id_num):
	data = SpecialPort.query.filter_by(id = id_num).first()
	db.session.delete(data)
	db.session.commit()
	page = request.args.get("page", "")
	return redirect('%s?user=All' %url_for('main.game_nmap'))


'''做中英文转换'''
def openvas_en2cn(english):
	save_data = En_To_Cn.query.filter_by( en = english ).first()	
	if save_data:
		return save_data.cn
	else:
		return ''


'''整理传入的数据将为导出excel做准备'''
def flush_excel(dbname, dbtype, user, data):

        '''连接zabbix数据库配置信息'''
        zabbix_info = ZabbixInfo.query.all()[0]

        '''用于将html get信息转换成字典'''
        datas = {}
        for a in data:
                b = a.split(':')
                datas[b[0]] = b[1]

	'''用户列表'''
	users = []
	if user == 'All':
		for user in dbname.query.all():
			users.append(user.operation_user)
	else:
		users.append(user)

	users_data = {}
	for user in list(set(users)):
		a2 = zabbix_login(zabbix_info.zabbix_server, (u'测试_%s' %user), 'VoeHy5bq0{xs')
		groupids_data = {}
		for groupid in datas.keys():
			hostnames = get_hostip(a2, groupid)[1]
			if datas[groupid] == 'None':
				hostids = dbname.query.filter_by(hostgroupid = groupid, operation_user = user).all()
				h_data = []
				for hid in hostids:
					a = hid.i_time
					t = time.strftime("%Y-%m-%d %H:%M:%S", a.timetuple())
					try:
						name = hostnames[hid.hostid]
					except:
						name = u"主机未找到"
					host_datas = [name, t]
					if hid.data:
						if dbtype == "ScanGroup":
							if json.loads(hid.data) != []:
								for d in json.loads(hid.data):
									_str = '%s %s' %(d[3],d[4])
									host_datas.append(_str)
								h_data.append(host_datas)
						elif dbtype == "OpenVAS":
							if json.loads(hid.data) != []:
								_list = []
								for d in json.loads(hid.data):
									if str(d.get('port_name','')) != "general":
										_str = '%s/%s' %(d.get('port_proto',''), d.get('port_name',''))
										h_data += [[ name, t,  _str, d.get('nvt_name',''), openvas_en2cn(d.get('nvt_name','')), 
													d.get('summary',''), openvas_en2cn(d.get('summary','')),
													d.get('solution',''),openvas_en2cn(d.get('solution','')) ]]
			else:
				h_data = []
				for hostid in datas[groupid].split(','):
					hid = dbname.query.filter_by(hostid = hostid, operation_user = user).first()
					if hid:
						a = hid.i_time
						t = time.strftime("%Y-%m-%d %H:%M:%S", a.timetuple())
						try:
							name = hostnames[hid.hostid]
						except:
							name = u"主机未找到"
						host_datas = [name, t]
						if hid.data:
							if dbtype == "ScanGroup":
								if json.loads(hid.data) != []:
									for d in json.loads(hid.data):
										_str = '%s %s' %(d[3],d[4])
										host_datas.append(_str)
									h_data.append(host_datas)
							elif dbtype == "OpenVAS":
								if json.loads(hid.data) != []:
									_list = []
	                                                                for d in json.loads(hid.data):
										if str(d.get('port_name','')) != "general":
	        	                                                                _str = '%s/%s' %(d.get('port_proto',''), d.get('port_name',''))
        	        	                                                        h_data += [[ name, t,  _str, d.get('nvt_name',''), openvas_en2cn(d.get('nvt_name','')),    
                                                                                                        d.get('summary',''), openvas_en2cn(d.get('summary','')),
                                                                                                        d.get('solution',''),openvas_en2cn(d.get('solution','')) ]]
			groupids_data[groupid] = h_data
		users_data[user] = groupids_data
	return (users_data, datas)





'''游戏服扫描'''
@main.route('/game/list', methods=['GET','POST'])
@login_required
def game_nmap():
	name = u"zabbix游戏服扫描"
        user = request.args.get('user', '')
	if request.args.get('filename', ''):
		filename = request.args.get('filename', '')
	else:
		filename = 'None'

	'''返回特殊端口信息'''
        port_db = SpecialPort.query.all()

	'''用有获取zabbix的配置信息'''
        zabbix_info = ZabbixInfo.query.all()[0]
        a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)

	'''通过zabbix API获取所有用户名信息'''
        scan_user = get_user(a)[0]

	'''用于从数据库中提取数据，如果是ALL则全部提取，否则就按照传入的user值提取'''	
	if user == 'All':
		scan_data = ScanGroup.query.all()
		a2 = a
		groupids = ScanGroup.query.all()
		groupids_list = []
		for groupid in groupids:
			groupids_list.append(groupid.hostgroupid)
		web_groupids = ','.join(list(set(groupids_list)))
	else: 
		scan_data = ScanGroup.query.filter_by(operation_user = user).all()
	        a2 = zabbix_login(zabbix_info.zabbix_server, (u'测试_%s' %user), 'VoeHy5bq0{xs')
		groupids_list = []
		for groupid in scan_data:
			groupids_list.append(groupid.hostgroupid)
		web_groupids = ','.join(list(set(groupids_list)))


        hostgroup = {}
        for data in scan_data:
                hostgroup[data.hostgroupid] = data.hostname

        group_hosts = {}
        hostnames = {}
	html_data = {}
        for hostgroupid, hostname in hostgroup.items():
                hostnames = dict(hostnames, **get_hostip(a2, hostgroupid)[1])
                host_dict = {}
                host_data = ScanGroup.query.filter_by(hostgroupid = hostgroupid).all()
                for h_data in host_data:
                        host_dict[h_data.hostid] = [h_data.ipaddr, h_data.i_time, h_data.operation_user, h_data.progress, h_data.data]
                group_hosts[hostgroupid] = host_dict

		h_data = ScanGroup.query.filter_by(hostgroupid = hostgroupid).all()
		html_host_data = {}
		for h in h_data:
			if h.data:
				html_host_data[h.hostid] = json.loads(h.data)
		html_data[hostgroupid] = html_host_data

		cmd = '''ps axu | grep "nmap -oX" | grep -v grep | grep -v sh | wc -l'''
	        np = int(os.popen(cmd).read())
	
	db_users = []
	for z in ScanGroup.query.all():
		db_users.append(z.operation_user)

        return render_template('game_nmap.html', name=name, scan_user=scan_user, hostgroup=hostgroup, group_hosts=group_hosts, 
				hostnames=hostnames, port_db=port_db, listname=user, html_data=html_data,  
				listuser=list(set(db_users)), filename=filename, web_groupids=web_groupids)


@main.route('/game/groups', methods=['GET','POST'])
@login_required
def game_groups():
	users = request.args.get('users', '').split(',')
	zabbix_server = ZabbixInfo.query.all()[0].zabbix_server
	zabbix_password = 'VoeHy5bq0{xs'
	total_scan_hosts = {}
	hosts = []
	for user in users:
		scan_data = ScanGroup.query.filter_by(operation_user = user).all()
		if scan_data:
			for data in scan_data:
				db.session.delete(data)
				db.session.commit()
		zabbix_user = u'测试_%s' % user
		a = zabbix_login(zabbix_server, zabbix_user, zabbix_password)
		for groupid, groupname in get_hostname(a).items():
			hostids = get_hostip(a, groupid)[0]
			for hostid, ipaddr in get_host(a, hostids).items():
				save_zabbix = ScanGroup( hostname=groupname, hostgroupid=groupid, ipaddr=ipaddr, hostid=hostid, operation_user=user )
				db.session.add(save_zabbix)
				db.session.commit()
				hosts.append(ipaddr)
			total_scan_hosts[groupid] = hosts

	Thread_Ip(scan_ips[:10])

	return redirect(("%s?user=All" % url_for('main.game_nmap')))


@main.route('/game/data', methods=['GET','POST'])
@login_required
def game_data():
        data_dict = {}
        db_data = ScanGroup.query.all()
	hostgroupids = []
        for i in db_data:
		hostgroupids.append(i.hostgroupid)
	
	datas = {}
	totalall = {}
	for hostgroupid in list(set(hostgroupids)):
		data = ScanGroup.query.filter_by(hostgroupid = hostgroupid).all()
		values = []
		for a in data:
			values.append(a.progress)
		try:
			datas[hostgroupid] = int(float(dict(Counter(values))[True]) / float(len(values)) * 100)
		except:
			datas[hostgroupid] = 0
	cmd = '''ps axu | grep "nmap -oX" | grep -v grep | grep -v sh | wc -l'''
	np = os.popen(cmd)
	a = {'nmap': np.read()}
	
	totalall['init'] = a 
	totalall['data'] = datas
	
        return json.dumps(totalall)


@main.route('/game/2excel', methods=['GET','POST'])
@login_required
def game_to_excel():
	user = request.args.get('user','')
	data = request.args.get('data','').split('$')

	users_data = flush_excel(ScanGroup, "ScanGroup", user, data)

	filename = 'game_nmap_%s.xlsx' % time.strftime("%Y-%m-%d")
	filepath = r'%s/app/static/files/%s' %(pick_path, filename)
	workbook = mkdir_file(filepath)

	port_db = SpecialPort.query.all()
        special_port = []
        for c in port_db:
                special_port.append(('%s open' %c.port))
	
	for user, groupidatas in users_data[0].items():
		worksheet = mkdir_worksheet(workbook, user)
		title = [u"游戏名称", u"扫描时间", u"扫描端口号"]
		total_data = []
		for groupid in users_data[1]:
			total_data += groupidatas[groupid]	
		mkdir_excel(workbook, worksheet, total_data, title, special_port)
	close_file(workbook)		
	save_file_info = ReportFileInfo(operation_user = current_user.username, file_form = u'端口扫描报告', file_name = filename )
        db.session.add(save_file_info)
	return redirect(("%s?user=All&filename=%s" % (url_for('main.game_nmap'), filename)))


@main.route('/openvas', methods=['GET','POST'])
@login_required
def game_openvas():
	name = u'oepnvas漏洞扫描'

	'''通过zabbixAPI获取前缀带有测试的用户名'''
	zabbix_info = ZabbixInfo.query.all()[0]
	a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)

	listname = request.args.get('user','')
	if request.args.get('filename', ''):
                filename = request.args.get('filename', '')
        else:
                filename = 'None'


	openvas = OpenVAS.query.all()
	hostgroups = []
	for hostgroup in openvas:
		hostgroups.append(hostgroup.hostgroupid)


	db_users = []
        for z in OpenVAS.query.all():
                db_users.append(z.operation_user)


	web_hostname_datas = {}
	web_hostname_hostids = {}	
	hostnames = {}
	for hostgroupid in list(set(hostgroups)):
		plans = []
		hostnames[hostgroupid] = get_hostip(a, hostgroupid)[1]
		hosts_info = []
		hostids = []	
		if listname == "All":
			all_data = OpenVAS.query.filter_by(hostgroupid = hostgroupid).all()
		else:
			all_data = OpenVAS.query.filter_by(hostgroupid = hostgroupid, operation_user = listname).all()

		for i in all_data: 
			hostids.append(i.hostid)
			hosts_info += [[i.hostid, i.ipaddr, i.i_time, i.operation_user, i.plan, i.data, i.progress]]
			plans.append(i.plan)
				
			
		web_hostname_hostids[hostgroupid] = hosts_info
		web_hostname_datas[hostgroupid] = [OpenVAS.query.filter_by(hostgroupid = hostgroupid).first().hostname, int(float(plans.count('100.0'))/float(len(hostids)) * 100), len(hostids)]
			

	return render_template('game_openvas.html', name=name, openvas=openvas, scan_user=get_user(a)[0], web_hostname_datas=web_hostname_datas, web_hostname_hostids=web_hostname_hostids, hostnames=hostnames, 
			listusers=list(set(db_users)), listname=listname, filename=filename)


'''通过post方式获取到前段传递回来的userid信息通过userid做端口扫描'''
@main.route('/openvas/scan', methods=['GET','POST'])
@login_required
def game_openvas_scan():
        openvas_ip = '58.229.184.39'
        admin_name = 'admin'
        admin_password = 'admin123'

	'''通过post接收到前段发来的用户名并转换成列表'''
	users = json.loads(request.get_data()).split(',')

	'''通过接收到的用户名获取到该zabbix用户下对应的主机列表'''
	zabbix_info = ZabbixInfo.query.all()[0]

	hosts = []
	for user in users:
		a = zabbix_login(zabbix_info.zabbix_server, (u'测试_%s' %user), 'VoeHy5bq0{xs')
		for groupid, groupname in get_hostname(a).items():
			hostids = get_hostip(a, groupid)[0]
			for hostid, ipaddr in get_host(a, hostids).items():
				if OpenVAS.query.filter_by(ipaddr=ipaddr).first():
					del_zabbix = OpenVAS.query.filter_by(ipaddr=ipaddr).first()
					db.session.delete(del_zabbix)
					db.session.commit() 
				save_zabbix = OpenVAS( hostname=groupname, hostgroupid=groupid, ipaddr=ipaddr, hostid=hostid, operation_user=user )
				db.session.add(save_zabbix)
				db.session.commit()
				hosts.append(str(ipaddr))
	Thread_openvas(hosts[:10], openvas_ip, admin_name, admin_password)
		
	return redirect(url_for('main.game_openvas'))
	

'''扫描漏洞信息展示'''
@main.route('/openvas/report', methods=['GET','POST'])
@login_required
def game_openvas_report():
	hostid = request.args.get('hostid', '')
	data = OpenVAS.query.filter_by( hostid = hostid ).first()
	name = u'%s漏洞扫描报告' % data.ipaddr
	translate_dict = {}
	for text in En_To_Cn.query.all():
		translate_dict[text.en] = text.cn
	return render_template('game_openvas_report.html', name=name, data=json.loads(data.data), scan_host = data.ipaddr, translate_dict=translate_dict)


'''用于保存纠错信息'''
@main.route('/openvas/save', methods=['GET','POST'])
@login_required
def game_openvas_save():
	datas = json.loads(request.get_data())
	en = datas['en']
	cn = datas['cn']
	save_data = En_To_Cn.query.filter_by( en = en ).first()
	save_data.cn = cn
	db.session.add(save_data)
	db.session.commit()  

'''openvas导出excel'''
@main.route('/openvas/2excel', methods=['GET','POST'])
@login_required
def openvas_to_excel():
	user = request.args.get('user','')
        data = request.args.get('data','').split('$')

	users_data = flush_excel(OpenVAS, "OpenVAS", user, data)
	filename = 'game_openvas_%s.xlsx' % time.strftime("%Y-%m-%d")
        filepath = r'%s/app/static/files/%s' %(pick_path, filename)
        workbook = mkdir_file(filepath)

	for user, groupidatas in users_data[0].items():
		worksheet = mkdir_worksheet(workbook, user)
		title = [u"游戏名称", u"扫描时间", u"扫描端口号", u"漏洞名称(英文)", u"漏洞名称(中文)", u"故障描述(英文)", u"故障描述(中文)", u"修复方法(英文)", u"修复方法(中文)"]
		total_data = []
		for groupid in users_data[1]:
			total_data += groupidatas[groupid]
		mkdir_excel(workbook, worksheet, total_data, title, special_port = False)
	close_file(workbook)
	save_file_info = ReportFileInfo(operation_user = current_user.username, file_form = u'openvas扫描报告', file_name = filename )
        db.session.add(save_file_info)
        return redirect(("%s?user=All&filename=%s" % (url_for('main.game_openvas'), filename)))	
		



@main.route('/files', methods=['GET','POST'])
@login_required
def report_files():
	name = u'文件生成历史记录'
	page = request.args.get('page','')
	file_type = []
	for f in ReportFileInfo.query.all():
		file_type.append(f.file_form)

	report_all = {}
	all_page = {}
	page_num = {}
	for f in list(set(file_type)):
		report = ReportFileInfo.query.order_by('id desc').filter_by(file_form = f).all()
		len_page = [report[i:i + 20] for i in range(0, len(report), 20)]
		try:
			report_all[f] = len_page[int(page) - 1]
		except:
			report_all[f] = len_page[0]
		all_page[f] = len_page 
		page_num[f] = len(len_page)
		
		
	label = request.args.get('label','')
	if request.args.get('del',''):
		id = request.args.get('del','')
		reportdel = ReportFileInfo.query.filter_by(id = id).first()
		db.session.delete(reportdel)
		db.session.commit()
		show_default = request.args.get('label','')
		return redirect(('%s?label=%s&page=%s' % (url_for('main.report_files'), label, page)))

	if label: 
		show_default = request.args.get('label','')
	else: 
		show_default = list(set(file_type))[0]

	return render_template('report_files.html', name=name, file_type = list(set(file_type)), report_all = report_all, all_page = all_page, page_num = page_num, show_default = show_default)


idc_dict = {'25': u'香港网速', '20': u'韩国KSDI', '18':u'台湾远传', '28':u'中华电信'}
@main.route('/report_traffic', methods=['GET','POST'])
@login_required
def report_traffic():
	name = u'流量报告'

	'''下载文件'''
	if request.args.get('filename', ''):
                filename = request.args.get('filename', '')
        else:
                filename = 'None'
	return render_template('report_traffic.html', name=name, idc_dict=idc_dict, filename=filename)


@main.route('/report_traffic/save', methods=['GET','POST'])
def report_traffic_save():
	zabbix_info = ZabbixInfo.query.all()[0]
	a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)

	idc = request.args.get('idc','')
	start_time = '%s0' % request.args.get('start_time','')[:17]
	
	'''配置索引的开始时间与结束时间'''
	s_time, e_time = change_stamp(start_time), change_stamp(start_time) + 1200
	
	game_list = get_gamename(a, idc)
	total_datas = return_datas(s_time, e_time, idc, game_list)

	time_value = []
	for stamp in range(s_time, e_time + 300, 300):
		t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(stamp)))
		time_value.append(t)

	print game_list

	return_d = []
	for gameid in game_list.keys():
		in_value, out_value = [], []
		for data in total_datas[gameid]:
			in_value.append(float(data[0]))
			out_value.append(float(data[1]))


		cut_in = [sum(in_value[i:i + 5]) / len(in_value[i:i + 5]) for i in range(0, len(in_value), 5)]
		cut_out = [sum(out_value[i:i + 5]) / len(out_value[i:i + 5]) for i in range(0, len(out_value), 5)]

		
		full_data = [[get_hostname(a)[gameid], time_value[_c], cut_in[_c], cut_out[_c]] for _c in range(0,len(time_value))]
		return_d += full_data

	filename = 'export_traffic_%s_%s.xlsx' % (idc_dict[idc], time.strftime("%Y-%m-%d"))
        filepath = r'%s/app/static/files/%s' %(pick_path, filename)
        workbook = mkdir_file(filepath)
	worksheet = mkdir_worksheet(workbook)
	title = [u'游戏名称', u'日期', u'输出流量', u'输入流量']
	mkdir_excel(workbook, worksheet, return_d, title, special_port = False)
	close_file(workbook)
	save_file_info = ReportFileInfo(operation_user = current_user.username, file_form = u'流量报告', file_name = filename )
	db.session.add(save_file_info)

	return redirect(("%s?idc=%s&filename=%s" % (url_for('main.report_traffic'), idc, filename)))
	


@main.route('/game_distribution', methods=['GET','POST'])
@login_required
def game_distribution():
        name = u'游戏分配'
        zabbix_info = ZabbixInfo.query.all()[0]
        a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)
        all_name = get_hostname(a)

        '''从数据库中读取信息'''
        game_list = Game_Distribution.query.all()

        excel_ids = request.args.get('excel_ids','')
        if excel_ids:

                excel_datas = []
                title = [u'游戏名称/版本', u'第一负责人', u'第二负责人', u'第三负责人']

                for data in game_list:
                        excel_datas += [[ all_name[data.gamename], data.first_name, data.second_name, data.third_name ]]
                filename = u'游戏跟进对应表_%s.xlsx' % time.strftime("%Y-%m-%d")
                filepath = r'%s/app/static/files/%s' %(pick_path, filename)
                workbook = mkdir_file(filepath)
                worksheet = mkdir_worksheet(workbook)
                mkdir_excel(workbook, worksheet, excel_datas, title, special_port = False)
                close_file(workbook)
                save_file_info = ReportFileInfo(operation_user = current_user.username, file_form = u'游戏跟进', file_name = filename )
                db.session.add(save_file_info)
                return redirect(("%s?filename=%s" % (url_for('main.game_distribution'), filename)))


        fcenter = FaultOperationsCenter.query.all()
        list_info2 = {}
        for k,v in get_hostname(a).items():
                if v.split('_')[0] in [u"港台", u"亚欧", u"韩国", u"国内"]:
                        list_info2[k] = v
        list_info = sorted(list_info2.iteritems(), key=lambda d:d[1], reverse = True)

        ids = request.args.get('ids','')
        if ids:
                for id in ids.split(','):
                        game = Game_Distribution.query.filter_by(id=id).first()
                        db.session.delete(game)
                db.session.commit()
                flash(u'删除成功')
                return redirect(url_for('main.game_distribution'))

        if request.args.get('filename', ''):
                filename = request.args.get('filename', '')
        else:
                filename = 'None'

        return render_template('manager_game.html', name =name, username = get_user(a)[0], hostgroup = list_info, fcenter = fcenter, filename = filename, all_name = all_name, game_list = game_list)

'''保存新的规则'''
@main.route('/game_distribution/save', methods=['GET','POST'])
@login_required
def game_distribution_save():
        zabbix_info = ZabbixInfo.query.all()[0]
        a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)
        datas = json.loads(request.get_data()).split(',')
        games = Game_Distribution(center = datas[0],
                gamename = datas[1],
                first_name = datas[2],
                first_phone = get_user_phone(a, datas[2]),
                second_name = datas[3],
                second_phone = get_user_phone(a, datas[3]),
                third_name = datas[4],
                third_phone = get_user_phone(a, datas[4]),
                vendor = datas[5],
                operations = datas[6],
                online = datas[7],
                PMname = datas[8])
        db.session.add(games)
        db.session.commit()


@main.route('/game_distribution/update', methods=['GET','POST'])
@login_required
def game_distribution_update():
        zabbix_info = ZabbixInfo.query.all()[0]
        a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)
        datas = json.loads(request.get_data())
        for id,value in datas.items():
                games = Game_Distribution.query.filter_by( id = id ).first()
                games.center = value[0]
                games.gamename = get_hostnameid(a, value[1])
                games.first_name = value[2]
                games.first_phone = get_user_phone(a, value[2]) 
                games.second_name = value[4]
                games.second_phone = get_user_phone(a, value[4])
                games.third_name = value[6]
                games.third_phone = get_user_phone(a, value[6])
                games.vendor = value[8]
                games.operations = value[9]
                games.online = value[10]
                games.PMname = value[11]
                db.session.add(games)
        db.session.commit()

'''刷新zabbix用户组权限策略'''
@main.route('/game_distribution/flush', methods=['GET','POST'])
@login_required
def game_distribution_flush():
        zabbix_info = ZabbixInfo.query.all()[0]
        a = zabbix_login(zabbix_info.zabbix_server, zabbix_info.zabbix_user, zabbix_info.zabbix_password)

        game_list = Game_Distribution.query.all()
        first_n, second_n, third_n = [], [], []
        for game in game_list:
                first_n.append(game.first_name)
                second_n.append(game.second_name)
                third_n.append(game.third_name)

        for user in list(set(first_n)):
                head = u"一负"
                hostgroupids = []
                for g in Game_Distribution.query.filter_by(first_name = user).all():
                        hostgroupids.append(g.gamename)
                usergroup_main(a, head, hostgroupids, user)

        for user in list(set(second_n)):
                head = u"二负"
                hostgroupids = []
                for g in Game_Distribution.query.filter_by(second_name = user).all():
                        hostgroupids.append(g.gamename)
                usergroup_main(a, head, hostgroupids, user)

        for user in list(set(third_n)):
                head = u"三负"
                hostgroupids = []
                for g in Game_Distribution.query.filter_by(third_name = user).all():
                        hostgroupids.append(g.gamename)
                usergroup_main(a, head, hostgroupids, user)

        flash(u'更新成功')
        return redirect(url_for('main.game_distribution'))

@main.route('/monitor_file', methods=['GET','POST'])
@login_required
def monitor_file():
	name = u'监控部署脚本'
	filepath = r'%s/app/static/update/' % pick_path
	if request.method == "POST":
		file = request.files['file']
		if file:
			filename = secure_filename(file.filename)
			selectfile = MonitorFile.query.filter_by( file_name = filename ).all()
			if selectfile:
				flash((u'文件名不能同名:%s' %filename))
				return redirect(url_for('main.monitor_file'))
			else:
				if MonitorFile.query.all():
					db_filename = MonitorFile.query.order_by('id desc').first().file_name
					if float(re.findall(r'\d.\d',filename)[0]) <= float(re.findall(r'\d.\d',db_filename)[0]):
						flash((u'%s 版本太低' %filename))
						return redirect(url_for('main.monitor_file'))		

			file.save(os.path.join(filepath, filename))
			save_monitor_file = MonitorFile(operation_user = current_user.username, file_name = filename)
			db.session.add(save_monitor_file)
			flash((u'%s文件已经上传' % filename))
			return redirect(url_for('main.monitor_file'))

	else:
		if request.args.get('del',''):
			id = request.args.get('del','')
			delfile = MonitorFile.query.filter_by( id = id ).first()
			db.session.delete(delfile)
			db.session.commit() 

	
	monitorfile = MonitorFile.query.all()
	text_info = {}
	for i in monitorfile:
		with open(('%s%s' %(filepath, i.file_name))) as f:
			text_info[i.id] = f.readlines()
	return render_template('monitor_file.html', name=name, monitorfile = monitorfile, text_info = text_info)	




def dns_information(w):
	dns_info = {}
	if type(w.updated_date).__name__ == 'list':
		dns_info['updated_date'] = w.updated_date[0].strftime('%Y-%m-%d')
	else:
		dns_info['updated_date'] = w.updated_date.strftime('%Y-%m-%d')
	dns_info['name'] = w.name
	dns_info['dnssec'] = w.dnssec
	dns_info['city'] = w.city
	if type(w.expiration_date).__name__ == 'list':
		dns_info['expiration_date'] = w.expiration_date[0].strftime('%Y-%m-%d')
	else:
		dns_info['expiration_date'] = w.expiration_date.strftime('%Y-%m-%d')
	dns_info['domain_name'] = w.domain_name
	dns_info['country'] = w.country
	dns_info['whois_server'] = w.whois_server
	dns_info['state'] = w.state 
	dns_info['registrar'] = w.registrar 
	dns_info['referral_url'] = w.referral_url
	dns_info['address'] = w.address
	if type(w.name_servers).__name__ == 'list':
		dns_info['name_servers'] = ','.join(w.name_servers)
	else:
		dns_info['name_servers'] = w.name_servers
	if type(w.creation_date).__name__ == 'list':
		dns_info['creation_date'] = w.creation_date[0].strftime('%Y-%m-%d')
	else:
		dns_info['creation_date'] = w.creation_date.strftime('%Y-%m-%d')

	if type(w.emails).__name__ == 'list':
		dns_info['emails'] = ','.join(w.emails)
	else:
		dns_info['emails'] = w.emails
	return json.dumps(dns_info)
	


@main.route('/manager_dns', methods=['GET','POST'])
@login_required
def manager_dns():
	name = u'Efun域名管理'
	delete = request.args.get('delete','')
	update = request.args.get('update','')
	domain = request.args.get('domain','')
	if update:
		for id in update.split(','):
			value = ManagerDns.query.filter_by( id = id ).first()
			w = whois.whois(value.dns_domain)
			if type(w.expiration_date).__name__ == 'list':
				value.dns_date_end = w.expiration_date[0].strftime('%Y-%m-%d')
			else:
				value.dns_date_end = w.expiration_date.strftime('%Y-%m-%d')
			value.dns_info = dns_information(w) 
			db.session.add(value)
			db.session.commit()
		return redirect(url_for('main.manager_dns')) 
		

	if delete:
		for id in delete.split(','):
			delinfo = ManagerDns.query.filter_by( id = id ).first()
			db.session.delete(delinfo)
			db.session.commit()

	if domain:
		try:
			w = whois.whois(domain)
		except:
			flash((u'%s域名不存在,请检查！' % domain))
			return redirect(url_for('main.manager_dns'))


		if type(w.expiration_date).__name__ == 'list':
			save_dns = ManagerDns( dns_domain = domain, dns_supplier = w.whois_server.split('.')[-2], dns_url = w.referral_url, dns_date_end = w.expiration_date[0].strftime('%Y-%m-%d'), dns_info = dns_information(w) ) 
		else:
			save_dns = ManagerDns( dns_domain = domain, dns_supplier = w.whois_server.split('.')[-2], dns_url = w.referral_url, dns_date_end = w.expiration_date.strftime('%Y-%m-%d'), dns_info = dns_information(w) ) 
		
		db.session.add(save_dns)
		db.session.commit()
		return redirect(url_for('main.manager_dns'))
		
		
		
	dns_all = ManagerDns.query.order_by('id desc').all()
	Due_date = {}
	dns_info = {}
	for dns in dns_all:
		Due_date[dns.id] = (change_stamp(dns.dns_date_end) - int(time.time())) / 86400 + 1
		dns_info[dns.id] = json.loads(dns.dns_info)
	en_to_cn = {'updated_date': u'更新日期', 'name': u'姓名', 'dnssec': u'DNS交互', 'city': u'城市', 'expiration_date': u'到期日期', 
		    'domain_name': u'域名', 'country': u'国家', 'whois_server': 'DNS供应商', 'state': u'状态', 'registrar': u'注册商',
		    'referral_url': u'注册商URL', 'address': u'地址', 'name_servers': u'域名服务器', 'creation_date': u'申请日期', 'emails': u'注册人邮箱'}
	return render_template('manager_dns.html', name=name, dns_all=dns_all, Due_date = Due_date, dns_info=dns_info, en_to_cn=en_to_cn)


@main.route('/save_dns', methods=['GET','POST'])
@login_required
def save_dns():
	data = json.loads(request.get_data())
	for id in data.keys():
		value = ManagerDns.query.filter_by( id = id ).first()
		value.dns_supplier = data[id][0]
		value.dns_url = data[id][1]
		db.session.add(value)
		db.session.commit()


@main.route('/manager_en2cn', methods=['GET','POST'])
@login_required
def manager_en2cn():
	name = u'中英对照表'
	en2cn = En_To_Cn.query.all()
	return render_template('manager_en2cn.html', name=name, en2cn=en2cn)


@main.route('/qyqq', methods=['GET','POST'])
@login_required
def qy_qq():
	app_id = "200634586"
	redirect_uri = "http://fb.efuntw.com/qq_login.shtml"
	state = "cThqYXBMc0MkUhI3MiUsBgVvUhkBFhctE1cpPgI9KyAadl1YBisYdg%3D%3D"
	pass
#	return 
#	return render_template('qq_test.html', app_id=app_id, redirect_uri=redirect_uri, state=state, title=title, test=test, datas=datas)



#@main.template_filter('reverse')
#def reverse_filter(s):
#	return s[::-1]
