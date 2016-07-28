Vagrant.configure(2) do |config|

  config.vm.box = "ubuntu/trusty64"
  config.vm.network "public_network"
  config.vm.provision "shell", inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y libffi-dev libssl-dev gconf-service libgconf-2-4 libgtk2.0-0 fonts-liberation libappindicator1 xdg-utils libpango1.0-0 python3-pip libxml2-dev python3-lxml libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev liblcms2-dev libwebp-dev tcl8.6-dev tk8.6-dev python-tk unzip xvfb libnss3-dev
    sudo apt-get -f install
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb >/dev/null 2>&1
    sudo dpkg -i google-chrome-stable_current_amd64.deb
    sudo pip3 install python-docx selenium Pillow nwdiag
    sudo pip3 install paramiko --upgrade
    sudo pip3 install requests --upgrade
    wget "http://chromedriver.storage.googleapis.com/$(curl -s "http://chromedriver.storage.googleapis.com/LATEST_RELEASE")/chromedriver_linux64.zip" >/dev/null 2>&1
    unzip chromedriver_linux64.zip
    sudo cp chromedriver /usr/local/bin/
    sudo cp /vagrant/xvfb /etc/init.d/
    sudo chmod +x /etc/init.d/xvfb
    sudo update-rc.d xvfb defaults
    sudo service xvfb start
    echo "export DISPLAY=:1" >> /home/vagrant/.bashrc
  SHELL
end
