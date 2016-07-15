#!/usr/bin/env python3

# Mangement Interface
# Get DHCP Range
# Split document into different sections

# Post creation report or data output
# store report in a per run basis, folder per customer, folder per run
# possibly store screenshots

# Gather environments fuel uuid
# Corp tools salesforce api token

# Upload

# process for creating new customer in salesforce
# salesforce pm Jenni Bader

# Add Entitlement & Timezone for customer info

# extra tests results for support:

# iostat disk IO
# benchmarking for nodes and controllers
# network IO
# disk * memory space
# sosreport is an example
# alex dobdin
# timmy tool

import zipfile,time,argparse,requests,json,sys,os,paramiko
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from docx import Document
from docx.shared import Inches
from docx.enum.style import WD_STYLE

# Handle Arguments
parser = argparse.ArgumentParser(description='Gather Fuel Screenshots')
parser.add_argument('-u', "--web-user", action="store", dest="web_username", type=str, help='Fuel Username',default="admin")
parser.add_argument('-p', "--web-pw", action="store", dest="web_password", type=str, help='Fuel Password',default="admin")
parser.add_argument('-su', "--ssh-user", action="store", dest="ssh_username", type=str, help='SSH Username',default="root")
parser.add_argument('-sp', "--ssh-pw", action="store", dest="ssh_password", type=str, help='SSH Password',default="r00tme")
parser.add_argument('-f', "--fuel", action="store", dest="host", type=str, help='Fuel FQDN or IP Ex. 10.20.0.2',required=True)
args = parser.parse_args()

def fuel_info():
    ssh = paramiko.SSHClient()
    fuel = {}
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(args.host, username=args.ssh_username, password=args.ssh_password)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("ip route ls | grep " + args.host + "| awk -e '{ print $3 }'")
    fuel['mangement_iface'] = ssh_stdout.readlines()[0].replace("\n","")
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("route -n | grep UG | awk -e '{ print $2 }'")
    fuel['gateway'] = ssh_stdout.readlines()[0].replace("\n","")
    # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("fuel plugins list")
    # print(ssh_stdout.readlines())

    fuel['url'] = "https://" + args.host + ":8443"
    fuel['ssh'] = {"username":args.ssh_username,"password":args.ssh_password}
    fuel['web'] = {"username":args.web_username,"password":args.web_password}
    fuel['horizon'] = "172.16.0.2" # get horizon address
    return fuel

# Get token from Keystone
def get_token():
    header = {"Content-Type": "application/json", 'accept': 'application/json'}
    creds = {"auth": {"tenantName": args.web_username,"passwordCredentials": {"username": args.web_username,"password": args.web_password}}}
    r = requests.post(url="https://" + args.host + ":8443/keystone/v2.0/tokens",headers=header,verify=False,json=creds)
    if r.status_code is not 200:
        sys.exit("Check Fuel username & password")
    return json.loads(r.text)['access']['token']['id']

# Get nodes from Fuel API
def get_nodes(token):
    header = {"X-Auth-Token": token,"Content-Type": "application/json"}
    return json.loads(requests.get(url="https://" + args.host + ":8443/api/nodes",headers=header, verify=False).text)

# Replaces items in the docx
def docx_replace(old_file,new_file,rep):
    zin = zipfile.ZipFile (old_file, 'r')
    zout = zipfile.ZipFile (new_file, 'w')
    for item in zin.infolist():
        buffer = zin.read(item.filename)
        if (item.filename == 'word/document.xml'):
            res = buffer.decode("utf-8")
            for r in rep:
                res = res.replace(r,rep[r])
            buffer = res.encode("utf-8")
        zout.writestr(item, buffer)
    zout.close()
    zin.close()

if not os.path.exists("docs"):
    os.makedirs("docs")

def gen_nodes_table(nodeData):
	# Generate row_count by counting the number of nodes and adding 1 for the header row
	row_count = len(nodeData)+1
	col_count = 6

	# Create (technically open) a new document
	doc = Document()

	# Add a heading; last digit is heading size
	doc.add_heading('Nodes(VMs)',1)

	# Create table for the data
	table = doc.add_table(row_count, col_count)
	table.style = 'TableGrid'

	# Generate the header row for the NodesVMS table
	hdr_cells = table.rows[0].cells
	hdr_cells[0].text = 'Hostname'
	hdr_cells[1].text = 'Role(s)'
	hdr_cells[2].text = 'Admin network IP address'
	hdr_cells[3].text = 'CPUxCores'
	hdr_cells[4].text = 'RAM'
	hdr_cells[5].text = 'HDD'

	# Modify each additional row using data for the node
	for nodeCounter, node in enumerate(nodeData):
		nodeRow = table.rows[nodeCounter+1].cells
		nodeRow[0].text = nodeData[nodeCounter]['hostname']
		nodeRow[1].text = {x+' ' for x in nodeData[nodeCounter]['roles']}
		nodeRow[2].text = nodeData[nodeCounter]['ip']
		nodeRow[3].text = str(nodeData[nodeCounter]['meta']['cpu']['total']) # Total or real?
		nodeRow[4].text = str(int(nodeData[nodeCounter]['meta']['memory']['total']/1048576)) + ' MB' # Total or max cap?
		nodeRow[5].text = {str(x['disk']) + ': ' + str(int(x['size']/1073741824)) + 'GB \n' for x in nodeData[nodeCounter]['meta']['disks']}
	doc.save('5.docs/NodesVMs.docx')

# 1.cover
entries = json.load(open("entries.json"))
entries['DATE'] = time.strftime("%d/%m/%Y")
docx_replace("templates/1.cover.docx","docs/1.cover.docx",entries)
print("Built docs/1.cover.docx")

# 2.intro

# print("Built docs/2.intro.docx")
# 3.architecture

# print("Built docs/3.architecture.docx")
# 4.network

# print("Built docs/4.network.docx")
# 5.access
fuel = fuel_info()
access = {
"FUELURL": fuel['url'],
"FUELIP": args.host,
"WEBUSER": fuel['web']['username'],
"WEBPW": fuel['web']['password'],
"HORURL": fuel['horizon'],
"SSHUSER": fuel['ssh']['username'],
"SSHUSER": fuel['ssh']['username'],
"SSHPW": fuel['ssh']['password']
}
docx_replace("templates/6.access.docx","docs/6.access.docx",access)
print("Built docs/6.access.docx")
# 6.fuel

token = get_token()
nodes = get_nodes(token)
gen_nodes_table(nodes)

#
replace = {
"TOTAL_NODES" : len(nodes)
}
for n in nodes:
    print( n['hostname'])

# print("Built docs/6.fuel.docx")
