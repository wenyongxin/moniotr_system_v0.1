#!/usr/bin/env python
#ecoding:utf-8

import socket
import sys
import termios
import tty
import paramiko
import select
import pickle
import time
from mysql_config import conn_mysql


'''创建连接mysql实例'''


def update_file(user, data):
	date =time.strftime('%Y_%m_%d %H:%M:%S')
	cursor = conn_mysql().cursor()
	sql = '''insert into ssh_history (user, date, history) values(%s, %s, %s)'''
	param = (user, date, data)
	cursor.execute(sql, param)


def interactive_shell(chan, loginuser, hostname):
    print """\033[;34m------ Welcome %s Login %s ------\033[0m""" % (loginuser, hostname)
    oldtty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        chan.settimeout(0.0)

	record = []
        while True:
	    r, w, e = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    x = chan.recv(1024)
                    if len(x) == 0:
                        print '\r\n*** EOF\r\n',
                        break
                    sys.stdout.write(x)
                    sys.stdout.flush()
                except socket.timeout:
                    pass

            if sys.stdin in r:
                x = sys.stdin.read(1)
                if len(x) == 0:
                    break
                record.append(x)
                chan.send(x)


	
	    if x == '\r':
	    	cmd = ''.join(record).split('\r')[-2]
		if len(cmd) != 0:
			update_file(loginuser, ('%s' %cmd))
	    
#	    if len(x) > 1 and len(x) != 0 and "]#" not in x:
#		if x:
#			update_file(loginuser, ('%s' %x))


    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)


def ssh_conn(hostname, port, password, login_user):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((hostname, port))
	except Exception as error:
		print '*** Connect failed: ' + str(error)
		sys.exit(1)

	try:
		username = 'root'
		t = paramiko.Transport(sock)
		t.start_client()
		t.auth_password(username, password)

		chan = t.open_session()
		chan.get_pty()
		chan.invoke_shell()
		interactive_shell(chan,login_user, username)
		chan.close()
		t.close()

	except (Exception, paramiko.AuthenticationException) as error:
		print error
		''' record login faile to opslog table'''
		try:
			t.close()
		except:
			pass
			sys.exit(1)


def open_pickle():
        with open('/tmp/ssh.pkl','r') as f:
                return pickle.load(f)


if __name__=="__main__":
	data = open_pickle()
	hostname = data['ipaddr']
	port = data['port']
	password = data['password']
	login_user = data['login_user']
	ssh_conn(hostname, port, password, login_user)



