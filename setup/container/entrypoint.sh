#!/bin/sh
set -eu

config=/etc/zenitiumdns
logs=/var/log/zenitiumdns
uid=1053
gid=1053

if [ "$(id -u)" = 0 ]
then
    mkdir -p "$config" "$logs"
    find "$config" "$logs" \( ! -user "$uid" -o ! -group "$gid" \) -exec chown -h "$uid:$gid" {} + 2>/dev/null || true
    exec su-exec "$uid:$gid" "$0" "$@"
fi

for dir in "$config" "$logs"
do
    if [ ! -w "$dir" ]
    then
        echo "ZenitiumDNS: $dir is not writable for uid $(id -u). Make the mounted directory writable for this user, for example with: chown -R $(id -u):$(id -g) <host directory>" >&2
        exit 1
    fi
done

if [ ! -f "$config/auth.config" ] && [ ! -f "$config/admin.password" ]
then
    password="$(head -c 18 /dev/urandom | base64 | tr -d '/+=\n')"
    (umask 0077 && printf '%s\n' "$password" > "$config/admin.password")
    echo "ZenitiumDNS: sign in to the web interface as admin with the password $password"
    echo "ZenitiumDNS: the password is also stored in $config/admin.password; change it after the first sign-in and the file is deleted automatically"
fi

exec /opt/zenitiumdns/ZenitiumDns "$config"
