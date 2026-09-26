#!/bin/sh

umask 0022

dotnetDir="/opt/dotnet"
dotnetVersion="10.0"
dotnetRuntime="Microsoft.AspNetCore.App 10.0."
dotnetUrl="https://dot.net/v1/dotnet-install.sh"

srcDir="$(cd "$(dirname "$0")" && pwd)"
dnsDir="/opt/zenitiumdns"
dnsConfig="/etc/zenitiumdns"
dnsLog="/var/log/zenitiumdns"

serviceName="zenitiumdns"
serviceUser="zenitiumdns"
installLog="$dnsDir/install.log"

echo ""
echo "====================="
echo "ZenitiumDNS Installer"
echo "====================="
echo ""

if [ ! -f "$srcDir/ZenitiumDns.dll" ]
then
    echo "Failed to install ZenitiumDNS: 'ZenitiumDns.dll' was not found in '$srcDir'."
    echo "Please run this script from the published ZenitiumDNS folder."
    exit 1
fi

if [ -f "$dnsDir/ZenitiumDns.dll" ]
then
    dnsUpdate="yes"
else
    dnsUpdate="no"
fi

mkdir -p $dnsDir
mkdir -p $dnsConfig

echo "" > $installLog

if dotnet --list-runtimes 2> /dev/null | grep -q "$dotnetRuntime";
then
    dotnetFound="yes"
else
    dotnetFound="no"
fi

if [ ! -d $dotnetDir ] && [ "$dotnetFound" = "yes" ]
then
    echo "ASP.NET Core Runtime is already installed."
else
    if [ -d $dotnetDir ] && [ "$dotnetFound" = "yes" ]
    then
        dotnetUpdate="yes"
        echo "Updating ASP.NET Core Runtime..."
    else
        dotnetUpdate="no"
        echo "Installing ASP.NET Core Runtime..."
    fi

    curl -sSL $dotnetUrl | bash /dev/stdin -c $dotnetVersion --runtime aspnetcore --no-path --install-dir $dotnetDir --verbose >> $installLog 2>&1

    if command -v apk >/dev/null 2>&1
    then
        echo "Installing ASP.NET Core Runtime dependencies..."
        apk add --no-cache libstdc++ >> $installLog 2>&1
    fi

    if [ ! -f "/usr/bin/dotnet" ]
    then
        ln -s $dotnetDir/dotnet /usr/bin >> $installLog 2>&1
    fi

    if dotnet --list-runtimes 2> /dev/null | grep -q "$dotnetRuntime";
    then
        if [ "$dotnetUpdate" = "yes" ]
        then
            echo "ASP.NET Core Runtime was updated successfully!"
        else
            echo "ASP.NET Core Runtime was installed successfully!"
        fi
    else
        echo "Failed to install ASP.NET Core Runtime. Please check '$installLog' for details."
        exit 1
    fi
fi

echo ""

if [ "$dnsUpdate" = "yes" ]
then
    echo "Updating ZenitiumDNS..."
    systemctl stop $serviceName.service >> $installLog 2>&1 || rc-service $serviceName stop >> $installLog 2>&1
else
    echo "Installing ZenitiumDNS..."
fi

if [ "$srcDir" != "$dnsDir" ]
then
    cp -R "$srcDir"/. "$dnsDir"/ >> $installLog 2>&1
fi

echo ""

if $( dotnet $dnsDir/ZenitiumDns.dll --icu-test >> $installLog 2>&1 ) >/dev/null 2>&1;
then
    echo "ICU package is already installed."
else
    echo "Checking for required ICU package..."

    if command -v apt-get >/dev/null 2>&1; then
        if ! dpkg -l | grep -q "libicu"; then
            echo "Installing required ICU package..."
            apt-get update >> $installLog 2>&1

            if apt-cache show libicu78 >/dev/null 2>&1; then
                echo "Installing libicu78 package..."
                apt-get install -y libicu78 >> $installLog 2>&1
            elif apt-cache show libicu76 >/dev/null 2>&1; then
                echo "Installing libicu76 package..."
                apt-get install -y libicu76 >> $installLog 2>&1
            elif apt-cache show libicu74 >/dev/null 2>&1; then
                echo "Installing libicu74 package..."
                apt-get install -y libicu74 >> $installLog 2>&1
            elif apt-cache show libicu72 >/dev/null 2>&1; then
                echo "Installing libicu72 package..."
                apt-get install -y libicu72 >> $installLog 2>&1
            elif apt-cache show libicu70 >/dev/null 2>&1; then
                echo "Installing libicu70 package..."
                apt-get install -y libicu70 >> $installLog 2>&1
            else
                echo "No specific libicu package was found, trying generic installation..."
                apt-get install -y libicu* >> $installLog 2>&1
            fi
        fi
    elif command -v dnf >/dev/null 2>&1; then
        if ! rpm -qa | grep -q "libicu"; then
            echo "Installing required ICU package..."
            dnf install -y libicu >> $installLog 2>&1
        fi
    elif command -v yum >/dev/null 2>&1; then
        if ! rpm -qa | grep -q "libicu"; then
            echo "Installing required ICU package..."
            yum install -y libicu >> $installLog 2>&1
        fi
    elif command -v zypper >/dev/null 2>&1; then
        if ! rpm -qa | grep -q "libicu"; then
            echo "Installing required ICU package..."
            zypper install -y libicu >> $installLog 2>&1
        fi
    elif command -v pacman >/dev/null 2>&1; then
        if ! pacman -Q | grep -q "icu"; then
            echo "Installing required ICU package..."
            pacman -S --noconfirm icu >> $installLog 2>&1
        fi
    elif command -v apk >/dev/null 2>&1; then
        if ! apk list --installed | grep -q "icu"; then
            echo "Installing required ICU package..."
            apk add --no-cache icu >> $installLog 2>&1
        fi
    else
        echo "Failed to install ZenitiumDNS: could not determine package manager to install ICU package. Please install ICU package manually and try again."
        exit 1
    fi

    if $( dotnet $dnsDir/ZenitiumDns.dll --icu-test >> $installLog 2>&1 ) >/dev/null 2>&1;
    then
        echo "ICU package was installed successfully!"
    else
        echo "Failed to install ZenitiumDNS: failed to install ICU package. Please install ICU package manually and try again."
        exit 1
    fi
fi

echo ""

if [ "$(ps --no-headers -o comm 1 | tr -d '\n')" = "systemd" ]
then
    if [ -f "/etc/systemd/system/$serviceName.service" ]
    then
        echo "Configuring permissions..."
        chown -R $serviceUser:$serviceUser $dnsDir $dnsConfig $dnsLog >> $installLog 2>&1

        echo "Restarting systemd '$serviceName' service..."
        systemctl restart $serviceName.service >> $installLog 2>&1
    else
        mkdir -p $dnsLog

        echo "Configuring user and permissions..."
        useradd --system -M --shell /usr/sbin/nologin --user-group $serviceUser >> $installLog 2>&1
        chown -R $serviceUser:$serviceUser $dnsDir $dnsConfig $dnsLog >> $installLog 2>&1

        echo "Configuring systemd '$serviceName' service..."
        cp $dnsDir/systemd.service /etc/systemd/system/$serviceName.service
        systemctl enable $serviceName.service >> $installLog 2>&1

        systemctl stop systemd-resolved >> $installLog 2>&1
        systemctl disable systemd-resolved >> $installLog 2>&1

        systemctl start $serviceName.service >> $installLog 2>&1

        if [ -f "/etc/NetworkManager/NetworkManager.conf" ]
        then
            currentVal=$(grep -F "dns=" /etc/NetworkManager/NetworkManager.conf)

            if [ "$currentVal" = "" ]
            then
                printf "\n[main]\ndns=none\n" >> /etc/NetworkManager/NetworkManager.conf 2>> $installLog
            elif [ "$currentVal" != "dns=none" ]
            then
                sed -i "s/$currentVal/dns=none/g" /etc/NetworkManager/NetworkManager.conf 2>> $installLog
            fi
        fi
        
        echo "Updating resolv.conf..."
        cp -a /etc/resolv.conf $dnsDir/resolv.conf.bak >> $installLog 2>&1    
        rm /etc/resolv.conf >> $installLog 2>&1    
        printf "# Generated by ZenitiumDNS Installer\n\nnameserver 127.0.0.1\n" > /etc/resolv.conf 2>> $installLog
    fi
elif [ -x "/sbin/rc-service" ]
then
    if [ -f "/etc/init.d/$serviceName" ]
    then
        echo "Configuring permissions..."
        chown -R $serviceUser:$serviceUser $dnsDir $dnsConfig $dnsLog >> $installLog 2>&1

        echo "Restarting OpenRC '$serviceName' service..."
        rc-service $serviceName stop >> $installLog 2>&1
        rc-service $serviceName start >> $installLog 2>&1
    else
        mkdir -p $dnsLog

        echo "Configuring user and permissions..."
        addgroup -S $serviceUser >> $installLog 2>&1
        adduser -H -S -D -s /bin/false -G $serviceUser $serviceUser >> $installLog 2>&1
        chown -R $serviceUser:$serviceUser $dnsDir $dnsConfig $dnsLog >> $installLog 2>&1

        echo "Configuring OpenRC '$serviceName' service..."
        cp $dnsDir/openrc.service /etc/init.d/$serviceName
        chmod +x /etc/init.d/$serviceName
        rc-update add $serviceName >> $installLog 2>&1
        rc-service $serviceName start >> $installLog 2>&1
        
        echo "Updating resolv.conf..."
        cp -a /etc/resolv.conf $dnsDir/resolv.conf.bak >> $installLog 2>&1    
        rm /etc/resolv.conf >> $installLog 2>&1    
        printf "# Generated by ZenitiumDNS Installer\n\nnameserver 127.0.0.1\n" > /etc/resolv.conf 2>> $installLog
    fi
else
    echo "Failed to install ZenitiumDNS: systemd/openrc was not detected."
    echo "Please install and configure the service manually for your distro."
    exit 1
fi 2>/dev/null

echo ""
echo "ZenitiumDNS was installed successfully!"
echo "Open http://$(cat /proc/sys/kernel/hostname):5380/ to access the web console."
echo ""
