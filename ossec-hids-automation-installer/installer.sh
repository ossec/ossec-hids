#!/usr/bin/bash
apt update && sudo apt upgrade
apt install -y php php-cli php-common libapache2-mod-php apache2-utils sendmail inotify-tools apache2 build-essential gcc make wget tar zlib1g-dev libpcre2-dev libpcre3-dev unzip libz-dev libssl-dev libpcre2-dev libevent-dev libsystemd0 libsystemd-dev build-essential
systemctl enable apache2
systemctl start apache2
a2enmod rewrite
systemctl restart apache2
wget https://github.com/ossec/ossec-hids/archive/3.7.0.tar.gz
tar -xvzf 3.7.0.tar.gz
cd ossec-hids-3.7.0/
bash install.sh
### UI
 rm -rf /var/www/html/*
cd /tmp/
git clone https://github.com/ossec/ossec-wui.git
mv /tmp/ossec-wui /var/www/html/
cd /var/www/html/ossec-wui
chown -R www-data:www-data /var/www/html/ossec-wui/
chmod -R 755 /var/www/html/ossec-wui/
systemctl restart apache2
target=$(hostname -I | awk '{print $1}')
echo "Open your browser on: HTTP://$target/ossec-wui/"

### Clean
cd 
 rm -rf ossec-hids-*
 mv installer.sh /tmp/ && rm -rf /tmp/installer.sh

  exit 0;
