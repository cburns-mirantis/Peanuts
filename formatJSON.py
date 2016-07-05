#!/usr/bin/python
# Takes in a json or xml file and makes it easier to read

import json
import xml.dom.minidom
import sys

if len(sys.argv) > 1:
	print "Creating formatted JSON file as 'formatted_"+sys.argv[1]+"'"
else:
	exit

filename = sys.argv[1]

if ".json" in filename:
	file = open(filename, 'r')
	parsedFile = json.loads(file.read())
	output = open("formatted_"+str(filename), 'w')
	output.write(json.dumps(parsedFile, indent=4, sort_keys=True))
	output.close()
else:
	print "Failed to create file 'formatted_"+filename+"'"
	exit
