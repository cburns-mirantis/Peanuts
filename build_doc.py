#!/usr/bin/env python3

import zipfile,time,argparse,requests,json,sys,os,paramiko,shutil,math,re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from PIL import Image
from docx import Document
from docx.shared import Inches
from selenium import webdriver
from collections import OrderedDict
from docx.enum.style import WD_STYLE
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException

# Handle Arguments
parser = argparse.ArgumentParser(description='Gather Fuel Screenshots')
parser.add_argument('-u', '--web-user', action='store', dest='web_username', type=str, help='Fuel Web Username',default='admin')
parser.add_argument('-p', '--web-pw', action='store', dest='web_password', type=str, help='Fuel Web Password',default='admin')
parser.add_argument('-wp', '--web-port', action='store', dest='web_port', type=str, help='Fuel Web Port',default='8443')
parser.add_argument('-su', '--ssh-user', action='store', dest='ssh_username', type=str, help='Fuel SSH Username',default='root')
parser.add_argument('-sp', '--ssh-pw', action='store', dest='ssh_password', type=str, help='Fuel SSH Password',default='r00tme')
parser.add_argument('-f', '--fuel', action='store', dest='host', type=str, help='Fuel FQDN or IP Ex. 10.20.0.2',required=True)
args = parser.parse_args()

# Get token from Keystone
def get_token():
    header = {'Content-Type': 'application/json', 'accept': 'application/json'}
    creds = {'auth': {'tenantName': args.web_username,'passwordCredentials': {'username': args.web_username,'password': args.web_password}}}
    r = requests.post(url='https://' + args.host + ':' + args.web_port + '/keystone/v2.0/tokens',headers=header,verify=False,json=creds)
    if r.status_code is not 200:
        sys.exit('Check Fuel username & password')
    return json.loads(r.text)['access']['token']['id']

# Get nodes from Fuel API
def get_nodes(token):
    header = {'X-Auth-Token': token,'Content-Type': 'application/json'}
    return sorted(json.loads(requests.get(url='https://' + args.host + ':' + args.web_port + '/api/nodes',headers=header, verify=False).text), key=lambda k: k['hostname'])

def fuel_info():
    ssh = paramiko.SSHClient()
    fuel = {}
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(args.host, username=args.ssh_username, password=args.ssh_password)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('ip route ls | grep ' + args.host + '| awk -e \'{ print $3 }\'')
    fuel['management_iface'] = ssh_stdout.readlines()[0].replace('\n','')
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('route -n | grep UG | awk -e \'{ print $2 }\'')
    fuel['gateway'] = ssh_stdout.readlines()[0].replace('\n','')
    # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('fuel plugins list')
    # print(ssh_stdout.readlines())

    fuel['url'] = 'https://' + args.host + ':' + args.web_port
    fuel['ssh'] = {'username':args.ssh_username,'password':args.ssh_password}
    fuel['web'] = {'username':args.web_username,'password':args.web_password}
    fuel['horizon'] = '172.16.0.2' # get horizon address
    return fuel

def gen_access_table(fuel):
   row_count = 8
   col_count = 3

   heading = runbook.add_heading('Access Information',level=1)
   heading.alignment = 1
   table = runbook.add_table(row_count, col_count)
   table.style = runbook.styles['Light Grid Accent 1']

   hdr_cells = table.rows[0].cells
   hdr_cells[0].text = 'Host'
   hdr_cells[1].text = 'IP address'
   hdr_cells[2].text = 'Comment(s)'

   line1 = table.rows[1].cells
   line1[0].text = 'Fuel UI Master Node URL'
   line1[1].text = fuel['url']

   line2 = table.rows[2].cells
   line2[0].text = 'Fuel UI Credentials'
   line2[1].text = fuel['web']['username'] + ' / ' + fuel['web']['password']

   line3 = table.rows[3].cells
   line3[0].text = 'Fuel Master Node IP'
   line3[1].text = args.host

   line4 = table.rows[4].cells
   line4[0].text = 'Fuel SSH Credentials (console)'
   line4[1].text = fuel['ssh']['username'] + ' / ' + fuel['ssh']['password']

   line5 = table.rows[5].cells
   line5[0].text = 'OpenStack Nodes SSH Credentials (console)'
   #line5[1].text = fuel['ssh']['username'] + ' / ' + fuel['ssh']['password']

   line6 = table.rows[6].cells
   line6[0].text = 'OpenStack Horizon URL'
   line6[1].text = fuel['horizon']

   line7 = table.rows[7].cells
   line7[0].text = 'OpenStack Credentials'
   line7[1].text = fuel['web']['username'] + ' / ' + fuel['web']['password']

# Replaces items in the docx
def docx_replace(old_file,new_file,rep):
    zin = zipfile.ZipFile (old_file, 'r')
    zout = zipfile.ZipFile (new_file, 'w')
    for item in zin.infolist():
        buffer = zin.read(item.filename)
        if (item.filename == 'word/document.xml'):
            res = buffer.decode('utf-8')
            for r in rep:
                res = res.replace(r,rep[r])
            buffer = res.encode('utf-8')
        zout.writestr(item, buffer)
    zout.close()
    zin.close()

def gen_nodes_table(nodeData):
   # Generate row_count by counting the number of nodes and adding 1 for the header row
   row_count = len(nodeData)+1
   col_count = 6

   # Add a heading; last digit is heading size
   heading = runbook.add_heading('Nodes(VMs)',level=1)
   heading.alignment = 1

   # Create table for the data
   table = runbook.add_table(row_count, col_count)
   table.style = runbook.styles['Light Grid Accent 1']

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
      nodeRow[5].text = [str(x['disk']) + ': ' + str(int(x['size']/1073741824)) + 'GB \n' for x in nodeData[nodeCounter]['meta']['disks']]

# Gathers network information on the cluster in question using the REST interface
def network_info(cluster_id):
    header = {'X-Auth-Token': token,'Content-Type': 'application/json'}
    network_data = json.loads(requests.get(url='https://' + args.host + ':' + args.web_port + '/api/clusters/' + str(cluster_id) + '/network_configuration/neutron/', headers=header, verify=False).text)
    networks = []
    for x in network_data['networks']:
        network = {}
        network['network_name'] = str(x['name']) if x['name'] is not None else 'no data'
        network['speed'] = 'no data'
        network['port_mode'] = 'no data'
        network['ip_range'] = str(x['cidr']) if x['name'] is not None else 'no data'# Check this - might be ['networks'][x]['ip_ranges'] instead
        network['vlan'] = str(x['vlan_start']) if x['vlan_start'] is not None else 'no data'
        network['interface'] = 'no data'
        network['gateway'] = str(x['gateway']) if x['gateway'] is not None else 'no data'
        networks.append(network)
    return networks

def gen_network_layout_table(networkData):
    row_count = len(networkData)+1
    col_count = 6

    runbook.add_heading('Network Layout',level=1)

    runbook.add_table(row_count, col_count)
    runbook.styles['Light Grid Accent 1']

    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Network name'
    hdr_cells[1].text = 'Speed'
    hdr_cells[2].text = 'Port mode'
    hdr_cells[3].text = 'IP Range'
    hdr_cells[4].text = 'VLAN'
    hdr_cells[5].text = 'Interface'

    for netCounter, network in enumerate(networkData):
      networkRow = table.rows[netCounter+1].cells
      networkRow[0].text = network['network_name']
      networkRow[1].text = network['speed']
      networkRow[2].text = network['port_mode']
      networkRow[3].text = network['ip_range']
      networkRow[4].text = network['vlan']
      networkRow[5].text = network['interface']

def screenshot(page,name,fix=False):
    if fix:
        driver.get('https://' + args.host + ':' + args.web_port)
        time.sleep(1)
    if page is not None:
        driver.get(page)
    time.sleep(1)
    total_width = driver.execute_script('return document.body.offsetWidth')
    total_height = driver.execute_script('return document.body.parentNode.scrollHeight')

    viewport_width = driver.execute_script('return document.body.clientWidth')
    viewport_height = driver.execute_script('return window.innerHeight')

    if total_height / viewport_height > 1 and total_height - viewport_height > 100 :
        passes = math.ceil(total_height / viewport_height)
        for i in range(passes):
            if i == 0:
                driver.save_screenshot('screens/' + name + '_0.png')
                continue
            driver.execute_script('window.scrollTo(0, '+ str(i*viewport_height) + ');')
            time.sleep(.2)
            driver.save_screenshot('screens/' + name + '_' + str(i) + '.png')
    elif total_height - viewport_height < 100:
        driver.execute_script('window.scrollTo(0, '+ str(viewport_height) + ');')
        time.sleep(.2)
        driver.save_screenshot('screens/' + name + '.png')
    else:
        driver.save_screenshot('screens/' + name + '.png')

def natural_sort_key(s):
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(re.compile('([0-9]+)'), s)]

# Initialiation
try:
    shutil.rmtree('screens/')
    os.makedirs('screens/')
except FileNotFoundError:
    os.makedirs('screens/')

# Handle chromedriver dependency
def cmd_exists(cmd):
    return any(
        os.access(os.path.join(path, cmd), os.X_OK)
        for path in os.environ['PATH'].split(os.pathsep)
    )
if not cmd_exists('chromedriver'):
    sys.exit('\nYou need chromedriver. Download from here:\nhttps://sites.google.com/a/chromium.org/chromedriver/downloads\n\nAnd install to your path:\nsudo cp chromedriver /usr/local/bin/')

token = get_token()
nodedata = get_nodes(token)
driver = webdriver.Chrome()
driver.set_window_size(1200, 1200)
driver.get('https://' + args.host + ':' + args.web_port)

# Handle Login
try:
    username = driver.find_element_by_name('username')
    username.send_keys(args.web_username)
    password = driver.find_element_by_name('password')
    password.send_keys(args.web_password)
except NoSuchElementException:
    driver.close()
    sys.exit('Login form not found. Do you have the correct address & port?')
password.send_keys(Keys.RETURN)
time.sleep(1)

# Get Fuel version
span_list = []
for v in driver.find_elements_by_tag_name('span'):
    span_list.append(v.text)
version = span_list[-1][:-2]

# Get environments
clusters = []
for a in driver.find_elements_by_tag_name('a'):
    if 'cluster/' in a.get_attribute('href'):
        clusters.append(a.get_attribute('href'))

screenshot(None,'fuel_evironments')
screenshot('https://' + args.host + ':' + args.web_port + '/#equipment','fuel_equipment')
screenshot('https://' + args.host + ':' + args.web_port + '/#releases','fuel_releases')
screenshot('https://' + args.host + ':' + args.web_port + '/#plugins','fuel_plugins')

# Environments screenshots
for c in clusters:
    driver.get(c + '/nodes')

    time.sleep(1)
    nodes = []
    for t in driver.find_elements_by_tag_name('a'):
        if 'node:' in t.get_attribute('href') and not 'node:null' in t.get_attribute('href'):
            nodes.append(t.get_attribute('href'))
    # Skip environment if it has no nodes
    if not nodes:
        continue
    for i,n in enumerate(nodes):
        results = re.search('cluster\/(\d+).*;node:(\d+)',n)
        cluster = results.group(1)
        node = results.group(2)
        if i == 0:
            screenshot(c + '/dashboard','env_' + cluster + '_dashboard',True)
            screenshot(c + '/nodes','env_' + cluster + '_nodes',True)
        screenshot(c + '/nodes/disks/nodes:' +node,'env_' + cluster + '_node_' + node + '_disk',True )
        screenshot(c + '/nodes/interfaces/nodes:' +node,'env_' + cluster + '_node_' + node + '_interfaces',True )


    driver.get(c + '/network')
    time.sleep(1)
    for i in range(len(driver.find_elements_by_tag_name('a'))):
        e = driver.find_elements_by_tag_name('a')[i]
        if 'subtab-link-' + e.text.lower().replace(' ','_') in e.get_attribute('class'):
            e.click()
            driver.execute_script('window.scrollTo(0,0);')
            time.sleep(.2)
            screenshot(None,'env_' + cluster + '_network_' + e.text.lower().replace(' ','_'))
        if 'Other' in e.text:
            e.click()
            time.sleep(1)
            screenshot(None,'env_' + cluster + '_network_other')
    driver.get(c + '/settings')
    time.sleep(1)
    for i in range(len(driver.find_elements_by_tag_name('a'))-1):
        e = driver.find_elements_by_tag_name('a')[i]
        if 'subtab-link-' + e.text.lower().replace(' ','_') in e.get_attribute('class'):
            e.click()
            driver.execute_script('window.scrollTo(0,0);')
            time.sleep(.2)
            screenshot(None,'env_' + cluster + '_settings_' + e.text.lower().replace(' ','_'))

driver.close()

files = [(x[0], time.ctime(x[1].st_ctime)) for x in sorted([(fn, os.stat('screens/' + fn)) for fn in os.listdir('screens/')], key = lambda x: x[1].st_ctime)]

for i,f in enumerate(files):
    im = Image.open('screens/' + f[0])
    im.save('screens/' + str(i) + '_' + f[0].replace('.png','.jpg'),'JPEG')
    os.remove('screens/' + f[0])

# Build cover page

entries = json.load(open('entries.json'))
entries['DATE'] = time.strftime('%d %B, %Y')
docx_replace('template.docx','cover.docx',entries)

runbook = Document('cover.docx')

# Generate the token for access

fuel = fuel_info()
gen_access_table(fuel)
runbook.add_page_break()

gen_nodes_table(nodedata)
# runbook.add_page_break()

# gen_network_layout_table(network_info(1))

runbook.add_page_break()
runbook.add_page_break()

files = os.listdir('screens/')
files.sort(key=natural_sort_key)

for i,f in enumerate(files):
    last = runbook.paragraphs[-1]
    p = last._element
    p.getparent().remove(p)
    p._p = p._element = None
    heading = runbook.add_heading(f.replace('.jpg',''), level=1)
    heading.alignment = 1
    runbook.add_picture('screens/' + f, width=Inches(6.5))
    pic = runbook.paragraphs[-1]
    pic.alignment = 1
    if i != len(files)-1:
        runbook.add_page_break()

runbook.save('Runbook - ' + entries['CUSTOMER'] + '.docx')

# Cleanup
shutil.rmtree('screens/')
os.remove('cover.docx')
