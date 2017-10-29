#!/usr/bin/env python

import MySQLdb

def conn_mysql():
        conn = MySQLdb.connect(host="127.0.0.1", user="root", passwd="p@ssw0rd", db="monitor", charset="utf8")
        return conn

