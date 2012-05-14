#! /bin/bash

/usr/sbin/accton
/usr/sbin/accton /var/account/pacct

rm -rf /var/psacct-collector /var/log/psacct-collector /tmp/psacct-collector
