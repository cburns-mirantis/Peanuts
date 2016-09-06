Vagrant.configure(2) do |config|

  config.vm.box = "ubuntu/trusty64"
  config.vm.network "public_network"
  config.vm.network "forwarded_port", guest: 80, host: 8080
  config.vm.provision "shell", inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y python3.4 apache2 libffi-dev libssl-dev gconf-service libgconf-2-4 libgtk2.0-0 fonts-liberation libappindicator1 xdg-utils libpango1.0-0 python3-pip libxml2-dev python3-lxml libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev liblcms2-dev libwebp-dev tcl8.6-dev tk8.6-dev python-tk unzip xvfb libnss3-dev
    sudo apt-get -f install
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb >/dev/null 2>&1
    sudo dpkg -i google-chrome-stable_current_amd64.deb
    sudo pip3 install python-docx selenium Pillow nwdiag tabulate python-novaclient
    sudo pip3 install paramiko --upgrade
    sudo pip3 install requests --upgrade
    wget "http://chromedriver.storage.googleapis.com/$(curl -s "http://chromedriver.storage.googleapis.com/LATEST_RELEASE")/chromedriver_linux64.zip" >/dev/null 2>&1
    unzip chromedriver_linux64.zip
    sudo cp chromedriver /usr/local/bin/
    sudo cp /vagrant/xvfb /etc/init.d/
    sudo chmod +x /etc/init.d/xvfb
    sudo update-rc.d xvfb defaults
    sudo service xvfb start
    sudo a2enmod cgi
    sudo echo "<Directory /var/www/html/cgi/>
    Options ExecCGI
    SetHandler cgi-script
    </Directory>" >> /etc/apache2/apache2.conf
    sudo service apache2 restart
    sudo mkdir /var/www/html/resources/
    sudo mkdir /var/www/html/cgi/
    sudo mkdir /var/www/html/runbooks/
    sudo cp /vagrant/resources/* /var/www/html/resources
    sudo cp /vagrant/cgi/report.py /var/www/html/cgi/
    sudo cp /vagrant/cgi/build_doc.py /var/www/html/cgi/
    sudo cp /vagrant/template.docx /var/www/html/cgi/
    sudo cp /vagrant/index.html /var/www/html/
    sudo chown -R www-data:www-data /var/www/html/
    sudo chmod -R og+xwr /var/www/html/
    sudo sed -i "s@www-data:/var/www:/usr/sbin/nologin@www-data:/var/www:/bin/bash@" /etc/passwd
    echo -n "Runbook Builder Address:"
    echo -n "http://localhost:8080"
  SHELL
end
