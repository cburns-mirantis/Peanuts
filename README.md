# Peanuts
Automated Documentation and Runbook Generation for Mirantis Services Deployed Clouds

This script is for automating the post deployment runbook.

TODO:

Output json
<<<<<<< HEAD
Add environment selector
Deployment how to links
Handle openoffice page breaks
switch for screenshotting all nodes instead of summary
auto version
patch 8 for cli health Check
screenshot setup steps for environment

Possibly remove equipment page as the environment nodes screenshot should have it already

Fixes:

Handle no gateway?
=======
Handle MOS 7
Handle slow environments
Add environment selector

Fixes:

>>>>>>> c701a386a8f48f4d230af7ad528138a5824889d2
management_iface handle domain names
Fix sorting of pictures
get cluster ids from API
get version from api
check per role, and only screenshot one per similar hosts
get speed correctly from environments
<<<<<<< HEAD
column widths for Result column in tables

=======
>>>>>>> c701a386a8f48f4d230af7ad528138a5824889d2

# Mangement Interface
# Get DHCP Range
# Split document into different sections

# Post creation report or data output
# store report in a per run basis, folder per customer, folder per run
# possibly store screenshots

# Gather environments fuel uuid
# Corp tools salesforce api token

# Upload

# process for creating new customer in salesforce
# salesforce pm Jenni Bader

# Add Entitlement & Timezone for customer info

# extra tests results for support:

# iostat disk IO
# benchmarking for nodes and controllers
# network IO
# disk * memory space
# sosreport is an example
# alex dobdin
# timmy tool

# Python's docx lib has an lxml dependency - do "pip3 install lxml" for Python3;
# if build fails, try doing "apt-get install libxml2-dev libxslt-dev" (possibly as root)
# and then re-run "pip3 install lxml"

Usage for when the environment has non-default credentials:

build_doc.py [-h] [-u WEB_USERNAME] [-p WEB_PASSWORD]
        [-su SSH_USERNAME] [-sp SSH_PASSWORD] -f HOST

Defaults for web credentials:

admin / admin

Defaults for ssh credentials:

root / r00tme

The minimum needed is the address to the fuel host. Can be FQDN or IP.

The script can be ran from the fuel host by using localhost, however the default interface will not be detected correctly.

The 'docs' directory will fill up with individual pages that can be merged.

Dependancy resolution:

Ubuntu:
1. Install pip3, libxml and unzip
  sudo apt-get install python3-pip libxml2-dev python3-lxml unzip
2. Install Chrome
  wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
  sudo dpkg -i google-chrome-stable_current_amd64.deb
3. Install python dependencies
  sudo pip3 install python-docx selenium
4. Install chromedriver
  https://sites.google.com/a/chromium.org/chromedriver/downloads
  wget http://chromedriver.storage.googleapis.com/2.22/chromedriver_linux64.zip
  unzip chromedriver_linux64.zip
  sudo cp chromedriver /usr/local/bin/

Centos:

Fedora:

Mac os:

1. Install python3 and chromedriver
  brew install python3 chromedriver
2. Install xcode
  xcode-select --install
3. Install python dependencies
  pip3 install python-docx selenium
4. Install Chrome
  https://www.google.com/chrome/browser/desktop/

Windows:

Vagrantfile:

This vagrant file sets up the dependencies in an Ubuntu VM and enables you to run build_doc.py completely from the command line and without taking up your screen.

1. git clone
2. cd runbook
3. vagrant up
4. vagrant ssh
5. cd /vagrant
6. ./build_doc.py -f 10.20.0.2
7. Output files will be created in the cloned directory where the Vagrantfile is on your host

NOTE: /vagrant directory is only available when starting the VM through 'vagrant up'

Adding styles to the document:

Credits:
