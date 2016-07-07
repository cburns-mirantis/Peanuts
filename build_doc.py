#!/usr/bin/env python3
import zipfile,time,argparse,paramiko,requests,json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parser = argparse.ArgumentParser(description='Gather Fuel Screenshots')
parser.add_argument('-c', "--customer", action="store", dest="customer", type=str, help='Customer Name',required=True)
parser.add_argument('-u', "--username", action="store", dest="username", type=str, help='SSH Username',required=True)
parser.add_argument('-p', "--password", action="store", dest="password", type=str, help='SSH Password',required=True)
parser.add_argument('-f', "--fuel", action="store", dest="host", type=str, help='Fuel FQDN or IP Ex. 10.20.0.2',required=True)
args = parser.parse_args()

def get_token():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(args.host, username=args.username, password=args.password)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("fuel token")
    return ssh_stdout.readlines()[0]

def get_nodes():
    header = {"X-Auth-Token": get_token(),
              "Content-Type": "application/json"}
    return json.loads(requests.get("https://" + args.host + ":8443/api/nodes",headers=header, verify=False).text)

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

nodes = get_nodes()

replace = {
"CUSTOMER" : args.customer,
"TOTAL_NODES" : len(nodes),
"DATE" : time.strftime("%d/%m/%Y")

}

print (replace)
# docx_replace("template.docx","runbook.docx",replace)
