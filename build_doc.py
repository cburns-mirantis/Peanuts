#!/usr/bin/env python3

# Mangement Interface
# Get DHCP Range
# Split document into different sections

# Post creation report or data output
# store report in a per run basis

import zipfile,time,argparse,requests,json,sys,os,paramiko
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Handle Arguments
parser = argparse.ArgumentParser(description='Gather Fuel Screenshots')
parser.add_argument('-u', "--username", action="store", dest="username", type=str, help='Fuel Username',default="admin")
parser.add_argument('-p', "--password", action="store", dest="password", type=str, help='Fuel Password',default="admin")
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

    fuel['url'] = "https://" + args.host + ":8443"

    fuel['ssh'] = {"username":args.ssh_username,"password":args.ssh_password}
    fuel['web'] = {"username":args.username,"password":args.password}

    return fuel

# Get token from Keystone
def get_token():
    header = {"Content-Type": "application/json", 'accept': 'application/json'}
    creds = {"auth": {"tenantName": args.username,"passwordCredentials": {"username": args.username,"password": args.password}}}
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

print(fuel_info())


# token = get_token()
# nodes = get_nodes(token)
# entries = json.load(open("entries.json"))
# entries['DATE'] = time.strftime("%d/%m/%Y")

# docx_replace("cover.docx","docs/1.cover.docx",entries)
#
# replace = {
# "TOTAL_NODES" : len(nodes)
# }
