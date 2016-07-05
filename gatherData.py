#!/usr/bin/python

import subprocess
import sys
import json

# Uses the Fuel API (as opposed to the CLI) to collect information about ...
# This is used for the creation of the runbook

def GetNetworkConfig(token, cluster_id):
	nodeCmd = 'curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/clusters/' + cluster_id + '/network_configurneutronn/ > network_config_' + cluster_id + '_data.json'
	subprocess.call(nodeCmd,shell=True)

def GetNodeData(token):
	#nodeCmd = 'curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/nodes/" + node + " > node" + node + "data.json'
	# Loops through a list of node IDs (string format)
	nodeList = [1,2,3,4]
	for node in nodeList:
		try:	
			nodeCmd = 'curl -H "X-Auth-Token: ' + token + '" -H "Content-Type:application/json" http://localhost:8000/api/nodes/' + str(node) + ' > node' + str(node) + 'data.json'
			subprocess.call(nodeCmd,shell=True)
		except:
			print "JSON collection for node " + node + " failed."
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
	
	# Make the API call and format the output
#	GetNodeData(token)
	GetNetworkConfig(token,'1')
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
