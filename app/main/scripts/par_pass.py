#ecoding=utf-8

import paramiko,os,time,json,pickle
from threading import Thread
from mysql_config import conn_mysql


local_path = os.getcwd() 

ssh_info, sftp_info = {}, {}
def paramiko_pass(ip, passwd, port, chmod_cmd, install_cmd):
	try:
		ssh = paramiko.SSHClient()
		ssh.load_system_host_keys()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(hostname=ip, username="root", password=passwd, port=int(port))
		stdin,stdout,stderr = ssh.exec_command(chmod_cmd)
		if stdout:
			stdiin,stdout,stderr = ssh.exec_command( install_cmd )
			stdout = stdout.read().split('\n')
			ssh_info["ok"] = stdout
			stderr = stderr.read().split('\n')
			ssh_info["err"] = stderr
		return ssh_info
	except StandardError,e:
		ssh_info["err"] = e

	
def paramiko_sftp(ip, passwd, port, filename):
	try:
		t = paramiko.Transport((ip, int(port)))
		t.connect(username="root", password=passwd)
		sftp = paramiko.SFTPClient.from_transport(t)

		remote_dir = "/root/%s" % filename
		local_dir = r'%s/app/static/update/%s' % (local_path, filename)

		sftp.put(local_dir,remote_dir)
		t.close()
		sftp_info['ftp'] = "%s %s is down." % (remote_dir, ip)
		return sftp_info
	except StandardError,e:
		ssh_info["err"] = e


def total(ip, passwd, port, filename, system, proxy ):
	chmod_cmd = 'chmod a+x /root/%s' % filename
	install_cmd = '/root/%s %s %s %s' %(filename, system, ip, proxy)
	paramiko_sftp(ip, passwd, port, filename)
	paramiko_pass(ip, passwd, port, chmod_cmd, install_cmd)
	cursor = conn_mysql().cursor()
	sql = "update machine set data=%s where ip=%s"
	param = (json.dumps(ssh_info), ip)
	cursor.execute(sql, param)
			


def par_pass_main(ips, passwd, port, filename, system, proxy, auto = 2):
	if auto == 1:
		total(ips, passwd, port, filename, system, proxy)
	else:
		sftp_thread = []
		for ip in ips:
			sftp_thread.append(Thread( target = total, args = (ip, passwd, port, filename, system, proxy) ))

		for sftp_object in sftp_thread:
			sftp_object.start()

		for sftp_object in sftp_thread:
			sftp_object.join()




if __name__=="__main__":
#	filename = 'test.sh'
	filename = 'install-agent.V0.9.sh'
	ips = ['172.16.5.242']
	port = 22
	passwd = '0new0rd'
	system = 'c'
	proxy = '103.227.128.16'
#	print par_pass_main(filename, ips, port, passwd, system, proxy )
	par_pass_main(ips, passwd, port, filename, system, proxy)	
