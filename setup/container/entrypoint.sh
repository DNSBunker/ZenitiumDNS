#!/bin/sh
set -eu

config=/etc/zenitiumdns

if [ ! -f "$config/auth.config" ] && [ ! -f "$config/admin.password" ]
then
    password="$(head -c 18 /dev/urandom | base64 | tr -d '/+=\n')"
    (umask 0077 && printf '%s\n' "$password" > "$config/admin.password")
    echo "ZenitiumDNS: sign in to the web interface as admin with the password $password"
    echo "ZenitiumDNS: the password is also stored in $config/admin.password; change it after the first sign-in and delete the file"
fi

exec /opt/zenitiumdns/ZenitiumDns "$config"
