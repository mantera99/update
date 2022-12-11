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
export OKEY="[${GREEN} OKEY ${NC}]";

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
     rm -f setup.sh;
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
   rm -rf ssh-vpn.sh
 else
   SKIP=true;
fi

function port-ssl() {
clear;
ssl="$(cat /etc/stunnel/stunnel.conf | grep -i accept | head -n 2 | cut -d= -f2 | sed 's/ //g' | tr '\n' ' ' | awk '{print $1}')"
ssl2="$(cat /etc/stunnel/stunnel.conf | grep -i accept | head -n 2 | cut -d= -f2 | sed 's/ //g' | tr '\n' ' ' | awk '{print $2}')"
echo -e "=======-CHANGE PORT STUNNEL4-========"
echo -e ""
echo -e "    [${GREEN}01${LIGHT}] PORT STUNNEL4 1 [ ${RED}$ssl${LIGHT} ]"
echo -e "    [${GREEN}02${LIGHT}] PORT STUNNEL4 2 [ ${RED}$ssl2${LIGHT} ]"
echo -e ""
echo -e "    [${GREEN}00${LIGHT}] ${RED}EXIT${LIGHT}"
echo -e ""
echo -e "====================================="
echo -e ""
read -p " Select Menu [ 1-2 or 0 ] :  " prot
echo -e ""
case $prot in
1)
read -p "NEW PORT STUNNEL4 1 : " stl
if [ -z $stl ]; then
echo "PLEASE INPUT PORT"
exit 0
fi
cek=$(netstat -nutlp | grep -w $stl)
if [[ -z $cek ]]; then
sed -i "s/$ssl/$stl/g" /etc/stunnel/stunnel.conf
sed -i "s/   - STUNNEL4                : ${ssl}, ${ssl2}/   - STUNNEL4                : ${stl}, ${ssl2}/g" /root/log-install.txt
/etc/init.d/stunnel4 restart > /dev/null
clear
echo -e "PORT ${GREEN}$stl${LIGHT} MODIFIES SUCCESS"
else
echo -e "PORT ${RED}$stl${LIGHT} IS USED"
fi
;;
2)
read -p "NEW PORT STUNNEL4 2 : " stl
if [ -z $stl ]; then
echo "PLEASE INPUT PORT"
exit 0
fi
cek=$(netstat -nutlp | grep -w $stl)
if [[ -z $cek ]]; then
sed -i "s/$ssl2/$stl/g" /etc/stunnel/stunnel.conf
sed -i "s/   - STUNNEL4                : ${ssl}, ${ssl2}/   - STUNNEL4                : ${ssl}, ${stl}/g" /root/log-install.txt
/etc/init.d/stunnel4 restart > /dev/null
clear
echo -e "PORT ${GREEN}$stl${LIGHT} MODIFIES SUCCESS"
else
echo -e "PORT ${RED}$stl${LIGHT} IS USED"
fi
;;
0)
exit
;;
*)
echo "Boh salah tekan" ; sleep 1 ; port-ssl ;;
esac
}

function port-xray() {
clear
# // Port Xray
export none="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS NTLS" | cut -d: -f2|sed 's/ //g')";
export xtls="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS TLS" | cut -d: -f2|sed 's/ //g')";
echo -e "========-CHANGE PORT TLS-========";
echo -e "";
echo -e "   [${GREEN}01${LIGHT}] PORT TLS   [ ${RED}${xtls}${LIGHT} ]";
echo -e "   [${GREEN}02${LIGHT}] PORT NTLS  [ ${RED}${none}${LIGHT} ]";
echo -e ""
echo -e "   [${RED}00${LIGHT}] ${RED}EXIT${LIGHT}";
echo -e "";
echo -e "=================================";
echo -e "";
read -p " Select Menu [ 1-2 or 0 ] :  "  port
echo -e "";
case $port in
1)
read -p "NEW PORT XRAY TLS : " xtls1
if [ -z $xtls1 ]; then
echo "PLEASE INPUT PORT"
exit 0
fi
cek=$(netstat -nutlp | grep -w $xtls1)
if [[ -z $cek ]]; then
sed -i "s/${xtls}/$xtls1/g" /usr/local/etc/xray/config.json
sed -i "s/   - OVPN WEBSOCKET TLS      : ${xtls}/   - OVPN WEBSOCKET TLS      : ${xtls1}/g" /root/log-install.txt
sed -i "s/   - SSH WEBSOCKET TLS       : ${xtls}/   - SSH WEBSOCKET TLS       : ${xtls1}/g" /root/log-install.txt
sed -i "s/   - VL/VM/TR/SS GRPC TLS    : ${xtls}/   - VL/VM/TR/SS GRPC TLS    : ${xtls1}/g" /root/log-install.txt
sed -i "s/   - XRAY VLESS TCP XTLS     : ${xtls}/   - XRAY VLESS TCP XTLS     : ${xtls1}/g" /root/log-install.txt
sed -i "s/   - XRAY VMESS TCP HTTP     : ${xtls}/   - XRAY VMESS TCP HTTP     : ${xtls1}/g" /root/log-install.txt
sed -i "s/   - XRAY TROJAN TCP         : ${xtls}/   - XRAY TROJAN TCP         : ${xtls1}/g" /root/log-install.txt
sed -i "s/   - XRAY VLESS WS TLS       : ${xtls}/   - XRAY VLESS WS TLS       : ${xtls1}/g" /root/log-install.txt
sed -i "s/   - XRAY VMESS WS TLS       : ${xtls}/   - XRAY VMESS WS TLS       : ${xtls1}/g" /root/log-install.txt
sed -i "s/   - XRAY TROJAN WS TLS      : ${xtls}/   - XRAY TROJAN WS TLS      : ${xtls1}/g" /root/log-install.txt
sed -i "s/   - XRAY SHDWSCK 22 WS TLS  : ${xtls}/   - XRAY SHDWSCK 22 WS TLS  : ${xtls1}/g" /root/log-install.txt
iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${xtls} -j ACCEPT
iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${xtls} -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${xtls1} -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${xtls1} -j ACCEPT
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save > /dev/null
netfilter-persistent reload > /dev/null
systemctl restart xray > /dev/null
clear;
echo -e "PORT ${GREEN}$xtls1${LIGHT} MODIFIED SUCCESS";
else
echo -e "PORT ${RED}$xtls1${LIGHT} ALREADY USED";
fi
;;
2)
read -p "NEW PORT XRAY NTLS : " none1
if [ -z $none1 ]; then
echo "PLEASE INPUT PORT"
exit 0
fi
cek=$(netstat -nutlp | grep -w $none1)
if [[ -z $cek ]]; then
sed -i "s/${none}/$none1/g" /usr/local/etc/xray/none.json
sed -i "s/   - SSH WEBSOCKET NONE      : ${none}/   - SSH WEBSOCKET NONE      : ${none1}/g" /root/log-install.txt
sed -i "s/   - XRAY VLESS WS NTLS      : ${none}/   - XRAY VLESS WS NTLS      : ${none1}/g" /root/log-install.txt
sed -i "s/   - XRAY VMESS WS NTLS      : ${none}/   - XRAY VMESS WS NTLS      : ${none1}/g" /root/log-install.txt
sed -i "s/   - XRAY TROJAN WS NTLS     : ${none}/   - XRAY TROJAN WS NTLS     : ${none1}/g" /root/log-install.txt
sed -i "s/   - XRAY SHDWSCK 22 WS NTLS : ${none}/   - XRAY SHDWSCK 22 WS NTLS : ${none1}/g" /root/log-install.txt
iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${none} -j ACCEPT
iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${none} -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${none1} -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${none1} -j ACCEPT
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save > /dev/null
netfilter-persistent reload > /dev/null
systemctl restart xray@none > /dev/null
clear;
echo -e "PORT ${GREEN}$none1${LIGHT} MODIFIED SUCCESS";
else
echo -e "PORT ${RED}$none1${LIGHT} ALREADY USED";
fi
;;
0)
exit
;;
*)
echo "Boh salah tekan" ; sleep 1 ; port-xray ;;
esac
}

function port-ovpn() {
clear
echo "hahaha"
sleep 1
menu
}

clear;
echo -e "";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${NC}${BG}               ⇱ PORT CHANGER ⇲                 ${BLUE}│${NC}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${LIGHT}  [${GREEN}01${LIGHT}] ${RED}•${LIGHT} CHANGE PORT STUNNEL4${NC}";
echo -e "${BLUE}│${LIGHT}  [${GREEN}02${LIGHT}] ${RED}•${LIGHT} CHANGE PORT TLS & NON TLS${NC}";
echo -e "${BLUE}│${NC}";
echo -e "${BLUE}│${LIGHT}  [${RED}00${LIGHT}] ${RED}• BACK TO MENU${NC}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}──────────────────────────────────────────────────${LIGHT}";
echo -e "";
echo -e -n " Select menu [${GREEN} 0 - 2 ${LIGHT}] = "; read x
if [[ $x = 1 || $x = 01 ]]; then  > /dev/null 2>&1;
 clear
 port-ssl
 elif [[ $x = 2 || $x = 02 ]]; then
 clear
 port-xray
 elif [[ $x = 3 || $x = 03 ]]; then
 clear
 port-ovpn
 elif [[ $x = 0 || $x = 00 ]]; then
 clear
 menu
else
 echo -e " PLEASE ENTER THE CORRECT NUMBER"
 sleep 1
 menu-port
fi
