#!/usr/bin/python

import subprocess
import sys
import json

# Uses the Fuel API (as opposed to the CLI) to collect information about ...
# This is used for the creation of the runbook

# Gather network configuration information and append relevant info to replaceList[]
def GetNetworkConfig(token, cluster_id, replaceList):
	# Fuel API call; response gets saved to "data" as JSON object
	data = json.loads(subprocess.check_output('curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/clusters/' + cluster_id + '/network_configuration/neutron/',shell=True))
	
	# Write output to a file for testing - REMOVE later
	output = open("network_config.json", "w")
	output.write(json.dumps(data, indent=4))
	output.close() 
	#replaceList.append(data['vips']['management']['namespace']

# Gather cluster and individual node information and append relevant info to replaceList[]
def GetNodeData(token, cluster_id, replaceList):
	# Start by gathering cluster information; save API response to data as JSON object
	data = json.loads(subprocess.check_output('curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/clusters/1/attributes/',shell=True))
	
	# Write output to a file for testing - REMOVE later
	output = open("cluster_" + cluster_id + "_info.json", "w")
	output.write(json.dumps(data, indent=4))
	output.close() 

	# Loops through a list of node IDs (string format) to gather node and (interface?) data
	nodeList = [1,2,3,4] #Hardcoded for now; change later
	NodesVMs = {}
	for node in nodeList:
		try:	
			data = json.loads(subprocess.check_output('curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/nodes/' + str(node),shell=True))
			output = open("node_" + str(node) + ".json", "w")
			output.write(json.dumps(data, indent=4))
			output.close()
			NodeInfo = {}
			NodeInfo['hostname'] = data['fqdn']
			NodeInfo['roles'] = data['roles'][0]
			NodesVMs['node_' + str(node)] = NodeInfo
		except:
			print "JSON collection for node " + node + " failed."
	outp = open("testwritejson.json","w")
	outp.write(json.dumps(NodesVMs,indent=4))
	outp.close()

	print "Finished collecting node data"
	#print NodesVMs

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
	
	replaceList = []
	# Make the API call and format the output
	GetNodeData(token, '1', replaceList)
	GetNetworkConfig(token, '1', replaceList)
	#print replaceList
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
