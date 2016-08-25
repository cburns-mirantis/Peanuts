#Peanuts
Automated Documentation and Runbook Generation for Mirantis Services Deployed Clouds

This script generates a runbook for use by Deployment or Support Engineers to generate a runbook template against a MOS instance.

## Defaults for web credentials:

`admin / admin`

## Defaults for ssh credentials:

`root / r00tme`

## Vagrantfile

This vagrant file sets up the dependencies and hosts the web app in an Ubuntu VM.

1. git clone https://github.com/cburns-mirantis/Peanuts
2. cd Peanuts
3. vagrant up
4. There will be a link to the Runbook Builder link like this

`==> default: Runbook Builder Address:
==> default: http://192.168.1.44`

5. Goto address and fill out form and click `Build Runbook`

#Adding styles to the document

To add a different style to the template document, you have to open the template.docx in Microsoft Word and add the style to an example item like a table. Then remove the item and save the file. The simple act of applying the style permanently adds it to the docx file, even if you delete the item.

#TODO

* Output json

* Deployment how to links

* switch for screenshotting all nodes instead of summary

* screenshot setup steps for environment

# Fixes

* Handle no gateway?

* management_iface handle domain names

* get speed correctly from environments

* column widths for Result column in tables

* Get DHCP Range

* store report in a per run basis, folder per customer, folder per run

# Credits
* Ramon Melero

* Matt Schafer

* Anton Moczygemba

* Jerry Keen

* Colin Burns
