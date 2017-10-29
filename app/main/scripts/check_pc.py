#!/usr/bin/env python
#ecoding:utf-8


import socket,paramiko
from multiprocessing import Process, Queue


q = Queue()


def check_port(ip, i, proxy, system):
	try:
		s = socket.socket()
		s.connect((ip, i[0]))	
		s.send("Hello")
		banner = s.recv(1024)
		if banner:
			check_pass(ip, int(i[0]), i[1], proxy, system)
	except:
		pass


def check_pass(ip, port, passwd, proxy, system):
	ssh = paramiko.SSHClient()
	ssh.load_system_host_keys()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh.connect(hostname=ip, username="root", password=passwd, port=int(port))
		stdin, stdout, stderr = ssh.exec_command('id')
		if stdout.read():
			oks = [ip, port, passwd, proxy, system]
			q.put(oks)
	except:
		pass



def run_process(ip, infos, proxy, system):
	threads = []
	for i in infos:
		threads.append(Process(target=check_port, args=(ip, i, proxy, system)))

	for t in threads:
		t.start()

	for t in threads:
		t.join()



def check_pc_main(ips, ports, passwords, proxy, system):
	infos = [ [port, passwd] for port in ports for passwd in passwords ]

	result = {}

	for ip in ips:
		run_process(ip, infos, proxy, system)

	while not q.empty():
		info = q.get()
		result[info[0]] = info[1:]

	return result










if __name__ == '__main__':
	ips = [u'172.16.5.240', u'172.16.5.243', u'172.16.5.15'] 
	ports = [36000, 22, 20755]
	passwords = [u'Efun@169', u'0new0rd', 'Efun@168'] 
	proxy = '103.227.128.16'
	system = 'c'
	print check_pc_main(ips, ports, passwords, proxy, system)

