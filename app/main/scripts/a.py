#!/usr/bin/env python
import os

cmd = '''ps axu | grep "nmap -oX" | grep -v grep | grep -v sh | wc -l'''
np = os.popen(cmd)
print np.read()
