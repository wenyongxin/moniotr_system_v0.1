#!/usr/bin/env python
#ecoding:utf-8

import dns.resolver
from dns.resolver import Resolver, NXDOMAIN, NoNameservers, Timeout, NoAnswer
from mysql_config import conn_mysql


def insert_database(cursor, num, id):
	sql = 'update report_dns set game_static=%s where id=%s'
	param = (num, id)
	cursor.execute(sql, param)
	


def check_dns():
	cursor = conn_mysql().cursor()
	cursor.execute('select * from report_dns')
	dns_all = cursor.fetchall()
	for i in range(0, len(dns_all)):
                id = int(dns_all[i][0])
                domain = str(dns_all[i][1])
                domain_type = str(dns_all[i][3])
                domain_add = str(dns_all[i][4])
		Mylist = {}
		
		try:
	                dnsinfo = dns.resolver.query(domain, domain_type)
			try:
                        	for i in dnsinfo.response.answer:
                                	for j in i.items:
                                       		if domain_type == "A":
                                                	ipaddr = j.address
	                                        elif domain_type == "CNAME":
        	                                        ipaddr = j.to_text()
		                        if domain_add in ipaddr:
						insert_database(cursor, 0, id)
		                        else:
						insert_database(cursor, 1, id)
			except:
				insert_database(cursor, 2, id)
                except NXDOMAIN:
			insert_database(cursor, 2, id)
		except NoNameservers:
			insert_database(cursor, 2, id)
		except Timeout:
			insert_database(cursor, 2, id)
		except NameError:
			insert_database(cursor, 2, id)
		except NoAnswer:
			insert_database(cursor, 2, id)
check_dns()
