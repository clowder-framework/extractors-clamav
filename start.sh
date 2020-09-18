#!/bin/sh

# create folder
mkdir -p /run/clamav
chown clamav.clamav /run/clamav

# update database
if [ ! -f /var/lib/clamav/daily.cvd ]; then
    /usr/bin/freshclam
fi
/usr/bin/freshclam -d -c 6

# start clamd
/usr/sbin/clamd

# start extractor
exec python clamav.py
