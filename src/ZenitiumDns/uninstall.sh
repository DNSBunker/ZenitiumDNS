#!/bin/sh

dotnetDir="/opt/dotnet"

dnsDir="/opt/zenitiumdns"
dnsConfig="/etc/zenitiumdns"
dnsLog="/var/log/zenitiumdns"

serviceName="zenitiumdns"
serviceUser="zenitiumdns"

echo ""
echo "======================="
echo "ZenitiumDNS Uninstaller"
echo "======================="

if [ -d $dnsDir ]
then
    echo ""
    echo "Uninstalling ZenitiumDNS..."

    rm /etc/resolv.conf >/dev/null 2>&1

    if [ -f "$dnsDir/resolv.conf.bak" ] || [ -L "$dnsDir/resolv.conf.bak" ]
    then
        cp -a $dnsDir/resolv.conf.bak /etc/resolv.conf >/dev/null 2>&1
    else
        printf "nameserver 8.8.8.8\nnameserver 1.1.1.1\n" > /etc/resolv.conf
    fi

    if [ "$(ps --no-headers -o comm 1 | tr -d '\n')" = "systemd" ] 
    then
        systemctl disable $serviceName.service >/dev/null 2>&1
        systemctl stop $serviceName.service >/dev/null 2>&1
        rm /etc/systemd/system/$serviceName.service >/dev/null 2>&1

        if [ -f "/etc/NetworkManager/NetworkManager.conf" ]
        then
            currentVal=$(grep -F "dns=" /etc/NetworkManager/NetworkManager.conf)

            if [ "$currentVal" = "dns=none" ]
            then
                sed -i "s/$currentVal/dns=default/g" /etc/NetworkManager/NetworkManager.conf >/dev/null 2>&1
            fi
        fi

        systemctl enable systemd-resolved >/dev/null 2>&1
        systemctl start systemd-resolved >/dev/null 2>&1

        userdel -f $serviceUser >/dev/null 2>&1
    elif [ -x "/sbin/rc-service" ]
    then
        rc-service $serviceName stop  >/dev/null 2>&1
        rc-update del $serviceName  >/dev/null 2>&1
        rm /etc/init.d/$serviceName >/dev/null 2>&1
        
        deluser $serviceUser >/dev/null 2>&1
    fi 2>/dev/null

    rm -rf $dnsDir >/dev/null 2>&1
fi

if [ -d $dotnetDir ]
then
    echo ""
    printf "Do you want to uninstall .NET Runtime (Y/n): "
    read -r answer0 < /dev/tty

    case "$answer0" in
        [Nn]* )
            echo ".NET Runtime was not uninstalled."
            ;;
        * )
            echo "Uninstalling .NET Runtime..."
            rm /usr/bin/dotnet >/dev/null 2>&1
            rm -rf $dotnetDir >/dev/null 2>&1
            ;;
    esac
fi

if [ -d "$dnsConfig" ]
then
    echo ""
    printf "Do you want to delete the '$dnsConfig' folder which contains all of the DNS server config files? (y/N): "
    read -r answer1 < /dev/tty

    case "$answer1" in
        [Yy]* )
            rm -rf "$dnsConfig" >/dev/null 2>&1
            echo "The '$dnsConfig' config folder was deleted successfully."
            ;;
        * )
            chown -R root:root "$dnsConfig" >/dev/null 2>&1
            echo "The '$dnsConfig' config folder was not deleted and it will be reused if you install the DNS server again."
            ;;
    esac
fi

if [ -d "$dnsLog" ]
then
    echo ""
    printf "Do you want to delete the '$dnsLog' folder which contains all of the DNS server log files? (y/N): "
    read -r answer2 < /dev/tty

    case "$answer2" in
        [Yy]* )
            rm -rf "$dnsLog" >/dev/null 2>&1
            echo "The '$dnsLog' logs folder was deleted successfully."
            ;;
        * )
            chown -R root:root "$dnsLog" >/dev/null 2>&1
            echo "The '$dnsLog' logs folder was not deleted."
            ;;
    esac
fi

echo ""
echo "Thank you for using ZenitiumDNS!"
echo ""
