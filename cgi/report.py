#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import cgi,cgitb,os,subprocess
cgitb.enable()
print('Content-Type: text/html;charset=utf-8')
print()
form = cgi.FieldStorage()

print("")

address = form.getvalue('address').replace('https://','')

if form.getvalue('web_port') is None:
    web_port = '8443'
else:
    web_port = form.getvalue('web_port')

if form.getvalue('web_user') is None:
    web_user = 'admin'
else:
    web_user = form.getvalue('web_user')

if form.getvalue('web_pass') is None:
    web_pass = 'admin'
else:
    web_pass = form.getvalue('web_pass')

if form.getvalue('ssh_user') is None:
    ssh_user = 'root'
else:
    ssh_user = form.getvalue('ssh_user')
if form.getvalue('ssh_pass') is None:
    ssh_pass = 'r00tme'
else:
    ssh_pass = form.getvalue('ssh_pass')


command = '/vagrant/build_doc.py'

if form.getvalue('ostf') is not None:
    command += ' -o'

command += ' -f ' + address + ' -wp ' + web_port + ' -hu \'' + web_user + '\' -hp \'' + web_pass + '\' -su \'' + ssh_user + '\' -sp \'' + ssh_pass + '\''
print(command)
# # try:
# #     print(os.system(command))
# # except:
# #     pass
# print(subprocess.call("pwd"))
# print(os.system("whoami"))
