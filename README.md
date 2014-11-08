gotls
=====

Test security features (ciphers, SPF and etc.) of MTA starttls.

Manual install
======
Using a Ubuntu 14.04 or Debian 7 + testing repo:
```
sudo apt-get install python3-dns* python3-spf python3-tz nmap python3-crypto openssl-blacklist-extra
wget http://xael.org/norman/python/python-nmap/python-nmap-0.3.4.tar.gz
sudo pip3.4 install python-nmap-0.3.4.tar.gz

