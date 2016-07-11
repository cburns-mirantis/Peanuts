#!/usr/bin/python

import subprocess
import sys
import json

# Uses the Fuel API (as opposed to the CLI) to collect information about ...
# This is used for the creation of the runbook

# Gathers information to replace tags that may not be collected from the other functions
def GetMiscTags(token, RepJSON):
	versionData = json.loads(subprocess.check_output('curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/version',shell=True))
	fuelVersion = versionData['release']
	openstackVersion = versionData['openstack_version']
	
	RepJSON['<fueldocversion>'] = 'https://docs.mirantis.com/openstack/fuel/' + fuelVersion + '/'

	# Network Layout - refactor with for loops later on
	RepJSON['<sp_ipmi>'] = 
	RepJSON['<port_mode_ipmi>'] = 
	RepJSON['<ip_range_ipmi>'] = 
	RepJSON['<vlan_ipmi>'] = 
	RepJSON['<interface_ipmi>'] = 

	RepJSON['<sp_pxe>'] = 
	RepJSON['<port_mode_pxe>'] = 
	RepJSON['<ip_range_pxe>'] = 
	RepJSON['<vlan_pxe>'] = 
	RepJSON['<interface_pxe>'] = 
	
	RepJSON['<sp_mgmt>'] = 
	RepJSON['<port_mode_mgmt>'] = 
	RepJSON['<ip_range_mgmt>'] = 
	RepJSON['<vlan_mgmt>'] = 
	RepJSON['<interface_mgmt>'] = 

	RepJSON['<sp_st_net>'] = 
	RepJSON['<port_mode_st_net>'] = 
	RepJSON['<ip_range_st_net>'] = 
	RepJSON['<vlan_st_net>'] = 
	RepJSON['<interface_st_net>'] = 
	
	RepJSON['<sp_pubnet>'] = 
	RepJSON['<port_mode_pubnet>'] = 
	RepJSON['<ip_range_pubnet>'] = 
	RepJSON['<vlan_pubnet>'] = 
	RepJSON['<interface_pubnet>'] = 
	
	RepJSON['<sp_pr_net>'] = 
	RepJSON['<port_mode_pr_net>'] = 
	RepJSON['<ip_range_pr_net>'] = 
	RepJSON['<vlan_pr_net>'] = 
	RepJSON['<interface_pr_net>'] = 

	# Access information
	RepJSON['<fuel_ui_credentials>'] = 
	RepJSON['<fuel_masternode_ip>'] =
	RepJSON['<fuel_ssh_credentials>'] =
	RepJSON['<os_node_ssh_cred>'] = 
	RepJSON['<os_horizon_url>'] = 
	RepJSON['<os_credentials>'] = 

	# Fuel Master Node Installation
	RepJSON['<fuel_hostname>'] = subprocess.check_output('hostname',shell=True)
	RepJSON['<fuel_interface>'] = 
	RepJSON['<fuel_pxe_interface>'] =
	RepJSON['<fuel_ip_addr>'] =
	RepJSON['<fuel_mgmt_interface>'] =
	RepJSON['<fuel_gateway>'] =
	RepJSON['<fuel_net_mask>'] =
	RepJSON['<fuel_dhcp_pool_range>'] =
	RepJSON['<fuel_domain>'] =
	RepJSON['<fuel_search_domain>'] =

# Gather network configuration information and add relevant info to JSON object
def GetNetworkConfig(token, cluster_id, replaceList, RepJSON):
	# Fuel API call; response gets saved to "data" as JSON object
	data = json.loads(subprocess.check_output('curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/clusters/' + cluster_id + '/network_configuration/neutron/',shell=True))
	
	# Write output to a file for testing - REMOVE later
	output = open("network_config.json", "w")
	output.write(json.dumps(data, indent=4))
	output.close() 

# Gather cluster and individual node information and use docx to fill in NodesVMs table (or external script)
def GetNodeData(token, cluster_id, RepJSON):
	# Start by gathering cluster information; save API response to data as JSON object
	data = json.loads(subprocess.check_output('curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/clusters/1/attributes/',shell=True))
	
	# Write output to a file for testing - REMOVE later
	output = open("cluster_" + cluster_id + "_info.json", "w")
	output.write(json.dumps(data, indent=4))
	output.close()

	# Loops through a list of node IDs (string format) to gather node and (interface?) data
	nodeList = [1,2,3,4] #Hardcoded for now; change later

	# NodesVMs is a runbook table that will be dynamically generated using the docx library
	NodesVMs = {}
	for node in nodeList:
		try:	
			data = json.loads(subprocess.check_output('curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/nodes/' + str(node),shell=True))
			#output = open("node_" + str(node) + ".json", "w")
			#output.write(json.dumps(data, indent=4))
			#output.close()
			
			NodeInfo = {}
			NodeInfo['hostname'] = data['fqdn']
			NodeInfo['roles'] = data['roles'][0]
			NodeInfo['admin_ip'] = data['ip']
			NodeInfo['CPUcores'] = subprocess.check_output("ssh " + data['ip'] + " 'cat /proc/cpuinfo | grep cores'")

			NodesVMs['node_' + str(node)] = NodeInfo
		except:
			print "JSON collection for node " + node + " failed."
	#outp = open("testwritejson.json","w")
	#outp.write(json.dumps(NodesVMs,indent=4))
	#outp.close()

	print "Finished collecting node data"

# Iteratively creates json files with data collected from the Fuel API
def GenDataFiles(tokenLoc):
	# Try using the command line arg as a path to the token
	try:
		file = open(tokenLoc,'r')
		token = file.read()
		file.close()
	# If that fails, try using the arg as the token itself (GenDataFiles() is called from within a try block)
	except:
		token = tokenLoc
	
	RepJSON = {}
	# Make the API calls and format the output from within each function
	GetNodeData(token, '1', RepJSON)
	GetNetworkConfig(token, '1', RepJSON)

	print "\nData generation successful."

# The first command line argument (after the script name) should either be a file containing the token or the token itself;
#  if neither are available, a new token will be automatically generated and used for the duration of the script.
def Main():
	if len(sys.argv)<2:
		print 'No token specified; creating new token'
		print 'Use "./gatherData.py <token or token file>" to specify token'
		tokenLoc = subprocess.check_output('fuel token',shell=True)
	else:
		try:
			tokenLoc = sys.argv[1]
		except:
			print "ERROR: Token not specified"
			exit
	try:
		print "Starting data collection\n"
		GenDataFiles(tokenLoc)
	except:
		print "ERROR: Could not load token file"
	

Main()