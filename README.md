#Peanuts
Automated Documentation and Runbook Generation for Mirantis Services Deployed Clouds

This script generates a runbook for use by Deployment or Support Engineers to generate a runbook template against a MOS instance.

## Defaults for web credentials:

`admin / admin`

## Defaults for Fuel ssh credentials:

`root / r00tme`

## Defaults for Vagrant vm ssh credentials:

`vagrant / vagrant`

## Vagrantfile

This vagrant file sets up the dependencies and hosts the web app in an Ubuntu VM.

1. git clone https://github.com/cburns-mirantis/Peanuts
2. cd Peanuts
3. vagrant up
4. The runbook builder will be available at http://localhost:8080

### Fuel directly accessible

5. Enter the address of the fuel server
6. Submit form and a download link will appear

### Fuel behind port forward

5.

#Adding styles to the document

To add a different style to the template document, you have to open the template.docx in Microsoft Word and add the style to an example item like a table. Then remove the item and save the file. The act of applying the style permanently adds it to the docx file, even if you delete the item.

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
