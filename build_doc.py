#!/usr/bin/env python3
import zipfile,time,argparse

parser = argparse.ArgumentParser(description='Gather Fuel Screenshots')
parser.add_argument('-c', "--customer", action="store", dest="customer", type=str, help='Customer Name',required=True)
args = parser.parse_args()

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

replace = {
"CUSTOMER" : args.customer,
"DATE" : time.strftime("%d/%m/%Y")
}

print (replace)
docx_replace("template.docx","runbook.docx",replace)
