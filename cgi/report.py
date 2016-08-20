#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import cgi,cgitb,os,subprocess
cgitb.enable()
print('Content-Type: text/html;charset=utf-8')
print()
form = cgi.FieldStorage()

print('')

address = form.getvalue('address').replace('https://','')
customer_name = form.getvalue('customer_name')
deployment_engineer = form.getvalue('deployment_engineer')
environment_type = form.getvalue('environment_type')
entitlement = form.getvalue('entitlement')
customer_manager = form.getvalue('customer_manager')

if form.getvalue('web_port'):
    web_port = form.getvalue('web_port')
else:
    web_port = '8443'

if form.getvalue('web_user'):
    web_user = form.getvalue('web_user')
else:
    web_user = 'admin'
if form.getvalue('web_pass'):
    web_pass = form.getvalue('web_pass')
else:
    web_pass = 'admin'
if form.getvalue('ssh_user'):
    ssh_user = form.getvalue('ssh_user')
else:
    ssh_user = 'root'
if form.getvalue('ssh_pass'):
    ssh_pass = form.getvalue('ssh_pass')
else:
    ssh_pass = 'r00tme'
if form.getvalue('horizon_user'):
    horizon_user = form.getvalue('horizon_user')
else:
    horizon_user = 'admin'
if form.getvalue('horizon_pass'):
    horizon_pass = form.getvalue('horizon_pass')
else:
    horizon_pass = 'admin'
if form.getvalue('timezone'):
    timezone = form.getvalue('timezone')
else:
    timezone = 'America/Central'

checks = []
if form.getvalue('ostf_sanity'):
    checks.append('sanity')
if form.getvalue('ostf_functional'):
    checks.append('smoke')
if form.getvalue('ostf_ha'):
    checks.append('ha')
if form.getvalue('ostf_platform'):
    checks.append('tests_platform')
if form.getvalue('ostf_cloud'):
    checks.append('cloudvalidation')
if form.getvalue('ostf_configuration'):
    checks.append('configuration')

command = '/vagrant/build_doc.py'

command += ' -f \'' + address
command += '\' -wp \'' + web_port
command += '\' -u \'' + web_user
command += '\' -p \'' + web_pass
command += '\' -su \'' + ssh_user
command += '\' -sp \'' + ssh_pass
command += '\'' + ' -cn \'' + customer_name
command += '\'' + ' -tz \'' + timezone
command += '\'' + ' -e \'' + entitlement
command += '\'' + ' -et \'' + environment_type
command += '\'' + ' -hp \'' + horizon_pass
command += '\'' + ' -hu \'' + horizon_user
command += '\'' + ' -de \'' + deployment_engineer + '\''
if customer_manager:
    command += '\'' + ' -cm \'' + customer_manager
    
for c in checks:
    command += ' -t \'' + c + '\''

print(command)
# # try:
# #     print(os.system(command))
# # except:
# #     pass
# print(subprocess.call('pwd'))
# print(os.system('whoami'))
