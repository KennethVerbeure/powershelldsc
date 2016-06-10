#!/bin/bash

DNS=$1
DOMAIN=$2
ADMINPASS="$3"
USER="$4"
PASS="$5"
ADMACHINENAME="$6"

dpkg -i awingu-license-certificate_99999_all.deb
python setup_awingu.py --dns $DNS --domain $DOMAIN --admin-pass "$ADMINPASS" --domain-admin "$USER" --domain-pass "$PASS" --ad-machine-name "$ADMACHINENAME"
