#!/usr/bin/env python3
import zipfile,time,argparse,requests,json,sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parser = argparse.ArgumentParser(description='Gather Fuel Screenshots')
parser.add_argument('-u', "--username", action="store", dest="username", type=str, help='Fuel Username',default="admin")
parser.add_argument('-p', "--password", action="store", dest="password", type=str, help='Fuel Password',default="admin")
parser.add_argument('-f', "--fuel", action="store", dest="host", type=str, help='Fuel FQDN or IP Ex. 10.20.0.2',required=True)
args = parser.parse_args()

def get_token():
    header = {"Content-Type": "application/json", 'accept': 'application/json'}
    creds = {"auth": {"tenantName": args.username,"passwordCredentials": {"username": args.username,"password": args.password}}}
    r = requests.post(url="https://" + args.host + ":8443/keystone/v2.0/tokens",headers=header,verify=False,json=creds)
    if r.status_code is not 200:
        sys.exit("Check Fuel username & password")
    return json.loads(r.text)['access']['token']['id']

def get_nodes():
    header = {"X-Auth-Token": get_token(),"Content-Type": "application/json"}
    return json.loads(requests.get(url="https://" + args.host + ":8443/api/nodes",headers=header, verify=False).text)

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
"CUSTOMER" : "Big Customer",
"ENV" : "Big Customer",
"RELEASE" : "Big Customer",
"CUSTOMER" : "Big Customer",
"TOTAL_NODES" : len(nodes),
"DATE" : time.strftime("%d/%m/%Y")

}

print (replace)
# docx_replace("template.docx","runbook.docx",replace)
