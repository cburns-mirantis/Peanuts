#!/usr/bin/python3
from docx import Document
from docx.shared import Inches

# Generate row_count by counting the number of nodes
row_count = 5
col_count = 6

# Create (technically open) a new document
doc = Document()

# Add a heading; last digit is heading size
doc.add_heading('Nodes(VMs)',1)

# Create table for the data
table = doc.add_table(row_count, col_count)
table.style = 'TableGrid'

# Modify the first row of the table
hdr_cells = table.rows[0].cells

hdr_cells[0].text = 'Hostname'
hdr_cells[1].text = 'Role'
hdr_cells[2].text = 'Admin network IP address'
hdr_cells[3].text = 'CPUxCores'
hdr_cells[4].text = 'RAM'
hdr_cells[5].text = 'HDD'

nodeList = [1,2,3,4]
# Modify each additional row using data for the node
for node in nodeList:
	nodeRow = table.rows[node].cells
	for cell in nodeRow:
		cell.text = 'test'
doc.save('test.docx')
