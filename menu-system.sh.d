#!/bin/bash
# (C) Copyright 2021-2022
# ==================================================================
# Name        : VPN Script Quick Installation Script
# Base        : WildyDev21
# Mod By      : Manternet
# ==================================================================

# // Export Color & Information
export RED='\033[0;31m';
export GREEN='\033[0;32m';
export BLUE='\033[0;34m';
export LIGHT='\033[0;37m';
export NC='\033[0m';
export BG='\e[30;5;47m'

# // Export Banner Status Information
export ERROR="${LIGHT}[${RED} ERROR ${LIGHT}]";
export INFO="[${YELLOW} INFO ${NC}]";
export OKEY="${GREEN}[${BLUE} OKEY ${NC}]";

# // Exporting maklumat rangkaian
source /root/ip-detail.txt;
export IP_NYA="$IP";

# // Getting
export IZIN=$(curl -sS https://raw.githubusercontent.com/Manpokr/mon/main/ip | awk '{print $4}' | grep $IP_NYA )
if [[ $IP_NYA = $IZIN ]]; then > /dev/null 2>&1;
     SKIP=true;
     clear
else
     echo -e "";
     echo -e " ${ERROR} PERMISION DENIED";
     rm -f ins-nginx.sh;
  exit 0;
fi

# // SC EXP
export DAY=$(date -d +1day +%Y-%m-%d)
export EXP=$(curl -sS https://raw.githubusercontent.com/Manpokr/mon/main/ip | grep $IP_NYA | awk '{print $3}')
export EXP1=$(echo $EXP | curl -sS https://raw.githubusercontent.com/Manpokr/mon/main/ip | grep $IP_NYA | awk '{print $3}')
 if [[ $EXP1 < $DAY ]]; then > /dev/null 2>&1;
   echo -e "";
   echo -e " ${ERROR} YOUR SCRIPT EXPIRED";
   exit 0
   rm -rf vpn.sh
 else
   SKIP=true;
fi

function add-host() {
# // Add Host
echo -e "${GREEN}"
        read -p "INPUT NEW DOMAIN = " host
        if [[ $host == "" ]]; then
            clear;
            echo ""
            echo -e " ${ERROR} PLEASE INPUT NEW DOMAIN TO CONTINUE";
            sleep 2
            add-host
        fi

echo -e "";
rm -f /usr/local/etc/xray/domain;
echo "$host" >> /usr/local/etc/xray/domain
export domain=$(cat /usr/local/etc/xray/domain)
export dom=$(cat /etc/xray/domain)

# // Mv
sed -i "s/ovpn.${dom}/ovpn.${domain}/g" /usr/local/etc/xray/none.json;
sed -i "s/ovpn.${dom}/ovpn.${domain}/g" /usr/local/etc/xray/config.json;
rm -f /etc/xray/domain;
echo "$host" >> /etc/xray/domain
echo -e "";
echo -e -n "${LIGHT}PRESS [ ${BLUE}ENTER${LIGHT} ] TO RENEW CERT ${NC}"; read  menu
clear
renew-cert
}

function renew-cert() {
domain=$(cat /usr/local/etc/xray/domain);
echo -e "";
echo -e "${OKEY} PROSES RENEW CERT.....";
echo -e "";

# // Stop Service
date
systemctl stop nginx
systemctl stop xray.service
systemctl stop xray@none.service

source ~/.bashrc
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d ${domain} -d ovpn.${domain} --standalone -k ec-256 --listen-v6 --force
~/.acme.sh/acme.sh --installcert -d ${domain} -d ovpn.${domain} --fullchainpath /usr/local/etc/xray/xray.crt --keypath /usr/local/etc/xray/xray.key --ecc

# // Restart Service
systemctl daemon-reload
systemctl restart nginx
systemctl restart xray.service
systemctl restart xray@none.service

echo -e "";
echo -e "${OKEY} CERT RENEW SUCCESS${NC}";
echo -e "";
echo -e -n "${LIGHT}PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu
menu
}

function set-dns() {
    cpath="/etc/openvpn/server/server-tcp.conf"
    echo -ne "PLEASE INPUT YOUR DNS [default: 8.8.8.8] : "
    read controld
    [[ -z $controld ]] && controld="8.8.8.8"
    [[ ! -f /etc/resolvconf/interface-order ]] && {
        apt install resolvconf
    }

    # Masukkan DNS kedalam server baru secara permenant
    echo "nameserver $controld" >/etc/resolvconf/resolv.conf.d/head

    # Masukkan DNS kedalam server baru secara sementara (Hilang selepas reboot)
    echo "nameserver $controld" >/etc/resolv.conf

    sed -i "/dhcp-option DNS/d" $cpath
    sed -i "/redirect-gateway def1 bypass-dhcp/d" $cpath
    cat >>$cpath <<END
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $controld"
END

    [[ ! -f /usr/bin/jq ]] && {
        apt install jq
    }
    bash <(curl -sSL https://raw.githubusercontent.com/nympho687/kirik/main/ceknet.sh)
    echo -ne "[ ${RED}WARNING${NC} ] Do you want to reboot now ? (y/n)? "
    read answer
    if [ "$answer" == "${answer#[Yy]}" ]; then
        exit 0
    else
        reboot
    fi
}

function cek-dns() {
    bash <(curl -sSL https://raw.githubusercontent.com/nympho687/kirik/main/ceknet.sh)
    echo -e -n "${LIGHT}PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu
    menu
}

clear;
echo -e "";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${NC}${BG}                ⇱ SYSTEM MENU ⇲                 ${BLUE}│${NC}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${LIGHT}  [${GREEN}01${LIGHT}] ${RED}•${LIGHT} ADD HOST";
echo -e "${BLUE}│${LIGHT}  [${GREEN}02${LIGHT}] ${RED}•${LIGHT} RENEW CERTV2RAY";
echo -e "${BLUE}│${LIGHT}  [${GREEN}03${LIGHT}] ${RED}•${LIGHT} CHANGE PORT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}04${LIGHT}] ${RED}•${LIGHT} BACKUP";
echo -e "${BLUE}│${LIGHT}  [${GREEN}05${LIGHT}] ${RED}•${LIGHT} RESTORE DATA";
echo -e "${BLUE}│${LIGHT}  [${GREEN}06${LIGHT}] ${RED}•${LIGHT} SET DNS";
echo -e "${BLUE}│${LIGHT}  [${GREEN}07${LIGHT}] ${RED}•${LIGHT} CHECK DNS";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}";
echo -e "${BLUE}│${LIGHT}  [${GREEN}08${LIGHT}] ${RED}•${LIGHT} LIMIT BANDWITH SPEED";
echo -e "${BLUE}│${LIGHT}  [${GREEN}09${LIGHT}] ${RED}•${LIGHT} SPEEDTEST";
echo -e "${BLUE}│${LIGHT}  [${GREEN}10${LIGHT}] ${RED}•${LIGHT} CLEAR-LOG";
echo -e "${BLUE}│${LIGHT}  [${GREEN}11${LIGHT}] ${RED}•${LIGHT} CLEAR-CACHE";
echo -e "${BLUE}│${LIGHT}  [${GREEN}12${LIGHT}] ${RED}•${LIGHT} RESTART ALL SERVICE";
echo -e "${BLUE}│${LIGHT}  [${GREEN}13${LIGHT}] ${RED}•${LIGHT} CHECK BANDWITH";
echo -e "${BLUE}│${LIGHT}  [${GREEN}14${LIGHT}] ${RED}•${LIGHT} WEBMIN";
echo -e "${BLUE}│${NC}";
echo -e "${BLUE}│${LIGHT}  [${RED}00${LIGHT}] ${RED}• BACK TO MENU${LIGHT}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}——————————————————————————————————————————————————${LIGHT}";
echo -e "";
echo -e -n " Select menu [${GREEN} 0 - 14 ${LIGHT}] = "; read x
if [[ $x = 1 || $x = 01 ]]; then > /dev/null 2>&1;
 clear
 add-host
 elif [[ $x = 2 || $x = 02 ]]; then
 clear
 renew-cert
 elif [[ $x = 3 || $x = 03 ]]; then
 clear
 menu-port
 elif [[ $x = 4 || $x = 04 ]]; then
 clear
 backup
 elif [[ $x = 5 || $x = 05 ]]; then
 clear
 restore
 elif [[ $x = 6 || $x = 06 ]]; then
 clear
 set-dns
 elif [[ $x = 7 || $x = 07 ]]; then
 clear
 cek-dns
 elif [[ $x = 8 || $x = 08 ]]; then
 clear
 limit-speed
 elif [[ $x = 9 || $x = 09 ]]; then
 clear
 speedtest
 elif [[ $x = 10 ]]; then
 clear
 clear-log
 elif [[ $x = 11 ]]; then
 clear
 clearcache
 elif [[ $x = 12 ]]; then
 clear
 restart
 elif [[ $x = 13 ]]; then
 clear
 menu-bw
 elif [[ $x = 14 ]]; then
 clear
 wbmn
elif [[ $x = 0 || $x = 00 ]]; then
clear
menu
else
echo -e " PLEASE ENTER THE CORRECT NUMBER"
 sleep 1
 menu-system
 fi
