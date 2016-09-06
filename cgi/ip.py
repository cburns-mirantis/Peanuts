#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import cgi,cgitb,os,time,subprocess
from subprocess import Popen, PIPE
cgitb.enable()

print('Status: 200\nContent-type: text/html\n')
print(os.environ['REMOTE_ADDR'])
