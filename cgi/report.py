#!/usr/bin/env python3.5
# -*- coding: UTF-8 -*-
import cgi,cgitb,os,time,subprocess
from subprocess import Popen, PIPE
cgitb.enable()
from subprocess import STDOUT, check_output
form = cgi.FieldStorage()

address = form.getvalue('fuel_address')
customer_name = form.getvalue('customer_name')
deployment_engineer = form.getvalue('deployment_engineer')
environment_type = form.getvalue('environment_type')
environment_id = form.getvalue('environment_id')
entitlement = form.getvalue('entitlement')
customer_manager = form.getvalue('customer_manager')

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
if form.getvalue('fuel_port'):
    fuel_port = form.getvalue('fuel_port')
else:
    fuel_port = '22'

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

filename = 'Runbook-%d.docx' % int(time.time())

command = 'cd /var/www/html/cgi/;DISPLAY=:1 ./build_doc.py'
command += ' --fuel-address \'' + address + '\''
command += ' --fuel-port \'' + fuel_port + '\''
command += ' --environment \'' + environment_id + '\''
command += ' --filename \'' + '/var/www/html/runbooks/' + filename + '\''
command += ' --web-user \'' + web_user + '\''
command += ' --web-pw \'' + web_pass + '\''
command += ' --ssh-user \'' + ssh_user + '\''
command += ' --ssh-pw \'' + ssh_pass + '\''
command += ' --customer-name \'' + customer_name + '\''
command += ' --time-zone \'' + timezone + '\''
command += ' --entitlement \'' + entitlement + '\''
command += ' --environment-type \'' + environment_type + '\''
command += ' --horizon-pw \'' + horizon_pass + '\''
command += ' --horizon-user \'' + horizon_user + '\''
if customer_manager:
    command += ' --customer-manager \'' + customer_manager + '\''
command += ' --deployment-engineer \'' + deployment_engineer + '\''
for c in checks:
    command += ' --test \'' + c + '\''

# proc = subprocess.Popen(command,stdout=PIPE,shell=True)
# stdout = proc.communicate()[0]


if proc.returncode is 0:
    print('Status: 200\nContent-type: text/html\n')
    print('<h1>Runbook Build Complete</h1>')
    print('<a href=\"http://' + os.environ['SERVER_NAME'] + '/runbooks/' + filename + '\" class=\"button expanded large\">Download</a>')
elif proc.returncode is 1:
    print('Status: 500\nContent-type: text/html\n')
    print('<h1>Error</h1>')
    print(command)
elif proc.returncode is 2:
    print('Status: 500\nContent-type: text/html\n')
    print('<h1>Fuel Error</h1>')
else:
    print('Status: 500\nContent-type: text/html\n')
    print('<h1>Fuel Error</h1>')
