#!/usr/bin/env python
#ecoding:utf-8

import os, json



header = 'Content-Type: application/json;charset=utf-8'
get_online = '{"cmd" : "get_online"}'
url = 'http://52.74.146.48:27183/sn.py'
cmd = r"curl -s --header '%s' -d '%s' '%s'" %(header, get_online, url)


def get_online():
	res = os.popen(cmd).read()
	info = json.loads(res)['result']['server_list']
	for i in info:
		print i


get_online()
	



