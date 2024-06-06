#!/usr/bin/bash
apt update && sudo apt upgrade
apt install -y php php-cli php-common libapache2-mod-php apache2-utils sendmail inotify-tools apache2 build-essential gcc make wget tar zlib1g-dev libpcre2-dev libpcre3-dev unzip libz-dev libssl-dev libpcre2-dev libevent-dev build-essential
