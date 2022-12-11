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

function add-trojan() {
clear
# // Add
export none="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS NTLS" | cut -d: -f2|sed 's/ //g')";
export xtls="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS TLS" | cut -d: -f2|sed 's/ //g')";

# // User
read -rp "USERNAME [ USER]    = " -e user
export user="$(echo ${user} | sed 's/ //g' | tr -d '\r' | tr -d '\r\n' )";

# // Validate Input
if [[ $user == "" ]]; then
    clear;
    echo "";
    echo -e " ${ERROR} PLEASE INPUT USERNAME";
    exit 1;
fi

# // Check User
if [[ "$( cat /usr/local/etc/xray/user.txt | grep -w ${user})" == "" ]]; then
    Do=Nothing;
else
    clear;
    echo -e "";
    echo -e " USERNAME [ ${RED}$user${LIGHT} ] ALREADY USE${NC} ";
    exit 1;
fi

# // Date && Bug
read -p "EXPIRED [ DAYS ]    = " masaaktif
read -p "SNI [ BUG ]         = " sni
read -p "SUBDOMAIN [ WILCD ] = " sub

# // Domain && Uuid
export domain=$(cat /usr/local/etc/xray/domain);
export dom=$sub$domain
export uuid=$(uuidgen);

# // Date && Exp
export hariini=`date -d "0 days" +"%Y-%m-%d"`
export exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
export exp1=`date -d "$masaaktif days" +"%d-%m-%Y"`

# // TR WS TLS
sed -i '/#trojanws$/a\### '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/trojan.json

# // TR GRPC
sed -i '/#trojangrpc$/a\### '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/trojan.json

echo -e "TR $user $exp" >> /usr/local/etc/xray/user.txt;

# // Link
export trojanlink1="trojan://${uuid}@${dom}:$xtls?type=ws&security=tls&path=/trojan&sni=${sni}#${user}";
export trojanlink2="trojan://${uuid}@${dom}:$none?host=${sni}&security=none&type=ws&path=/trojan-none#${user}";
export trojanlink3="trojan://${uuid}@$dom:${xtls}?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${sni}#${user}";

systemctl restart xray@trojan.service

clear;
echo -e "=======-XRAY-TROJAN/WS&GRPC-=======";
echo -e "REMARKS   = ${user}";
echo -e "MYIP      = ${IP_NYA}";
echo -e "SUBDOMAIN = ${dom}";
echo -e "PORT TLS  = ${xtls}";
echo -e "PORT NONE = ${none}";
echo -e "PASSWORD  = ${uuid}";
echo -e "===================================";
echo -e "TROJAN WS TLS LINK";
echo -e " ${trojanlink1} ";
echo -e "";
echo -e "===================================";
echo -e "TROJAN WS LINK";
echo -e " ${trojanlink2} ";
echo -e "";
echo -e "===================================";
echo -e "TROJAN GRPC TLS LINK";
echo -e " ${trojanlink3} ";
echo -e "";
echo -e "===================================";
echo -e "EXPIRED   = $exp1";
echo -e "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu
menu
}

function del-trojan() {
clear
# // Del Trojan
export NUMBER_OF_CLIENTS=$(grep -c -E "^TR " "/usr/local/etc/xray/user.txt");
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo "";
		echo -e " ${ERROR} NO USER IN VPS";
		exit 1
	fi
	echo "";
	echo " ====-DELETE USER TROJAN-====";	
	echo "     NO USER  EXPIRED";
	grep -E "^TR " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2-4 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
	echo " ============================";
	read -rp " Select Number [1]: " CLIENT_NUMBER
	else
	echo " ============================";
	read -rp " Select Number [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
	fi
	done
export user=$(grep -E "^TR " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p);
export exp=$(grep -E "^TR " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p);

sed -i "/\b$user\b/d" /usr/local/etc/xray/user.txt
sed -i "/^### $user $exp/,/^},{/d" /usr/local/etc/xray/trojan.json
systemctl restart xray@trojan.service

clear
echo "";
echo "====-USER TROJAN DELETE-====";
echo " USERNAME  = $user";
echo " EXPIRED   = $exp";
echo "============================";
echo "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU TROJAN${NC}"; read  menu
menu-trojan
}

function renew-trojan() {
clear
# // Renew Trojan
export NUMBER_OF_CLIENTS=$(grep -c -E "^TR " "/usr/local/etc/xray/user.txt");
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		clear
		echo "";
		echo -e " ${ERROR} NO USER IN VPS";
		exit 1
	fi

	clear
	echo "";
	echo -e "====-RENEW CLIENT TROJAN-====";
	grep -E "^TR " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2-3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
           echo "=============================";
			read -rp "Select Menu [1]: " CLIENT_NUMBER
		else
           echo "=============================";
			read -rp "Select Menu [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done
        echo ""
        read -p "EXPIRED [ DAYS ] = " masaaktif

# // User && Exp
export user=$(grep -E "^TR " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p);
export exp=$(grep -E "^TR " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p);
export now=$(date +%Y-%m-%d);
export d1=$(date -d "$exp" +%s);
export d2=$(date -d "$now" +%s);
export exp2=$(( (d1 - d2) / 86400 ));
export exp3=$(($exp2 + $masaaktif));
export exp4=`date -d "$exp3 days" +"%Y-%m-%d"`

sed -i "s/TR $user $exp/TR $user $exp4/g" /usr/local/etc/xray/user.txt
sed -i "s/### $user $exp/### $user $exp4/g" /usr/local/etc/xray/trojan.json

systemctl restart xray@trojan.service

clear
echo "";
echo "====-CLIENT TROJAN RENEW-====";
echo " USERNAME  = $user";
echo " ADDED     = $now";
echo " EXPIRED   = $exp4";
echo "=============================";
echo "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU TROJAN${NC} "; read  menu
menu-trojan
}

function cek-trojan() {
clear
# // CEK ACCOUNT
export ACC_NYA=$(grep -c -E "^TR " "/usr/local/etc/xray/user.txt")
if [[ ${ACC_NYA} == '0' ]]; then
   echo ""
   echo -e " ${ERROR} YOU DON'T HAVE A TROJAN ACCOUNT !!!";
   sleep 1
   menu-trojan
fi

# // CEK TROJAN
echo -n > /tmp/other.txt
data=( `cat /usr/local/etc/xray/user.txt | grep "^TR " | cut -d ' ' -f 2 | sort | uniq`);
echo -e "";
echo -e " ======-TROJAN USER LOGIN-======";
for akun in "${data[@]}"
do
echo -n > /tmp/iptrojan.txt
data2=( `cat /var/log/xray/access.log | grep "$(date -d "0 days" +"%H:%M" )" | tail -n150 | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | sort | uniq`);
for ip in "${data2[@]}"
do

jum=$(cat /var/log/xray/access.log | grep "$(date -d "0 days" +"%H:%M" )" | grep -w $akun | tail -n150 | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | grep -F $ip | sed 's/2402//g' | sort | uniq)
if [[ "$jum" = "$ip" ]]; then
echo "$jum" >> /tmp/iptrojan.txt
else
echo "$ip" >> /tmp/other.txt
fi
jum2=$(cat /tmp/iptrojan.txt)
sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
done

jum=$(cat /tmp/iptrojan.txt)
if [[ "$jum" = "$akun" ]]; then
echo > /dev/null
else
jum2=$(cat /tmp/iptrojan.txt | nl -s ' • ')
echo -e "  USER = $akun";
echo -e "$jum2";
echo -e " ===============================";
fi
rm -rf /tmp/iptrojan.txt
done
rm -rf /tmp/iptrojan.txt
rm -rf /tmp/other.txt
echo -e -n " PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU TROJAN${NC}"; read  menu
menu-trojan
}

function trial-trojan() {
clear
# // Trial Trojan
export xtls="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS TLS" | cut -d: -f2|sed 's/ //g')";
export none="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS NTLS" | cut -d: -f2|sed 's/ //g')";

export user=TRIALtrojan-`</dev/urandom tr -dc X-Z0-9 | head -c4`
export exp=1

read -p "SNI [ BUG ]         = " sni
read -p "SUBDOMAIN [ WILCD ] = " sub

# // Domain && Uuid
export domain=$(cat /usr/local/etc/xray/domain);
export dom=$sub$domain
export uuid=$(uuidgen);

# // Date && Exp
export hariini=`date -d "0 days" +"%Y-%m-%d"`
export exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
export exp1=`date -d "$masaaktif days" +"%d-%m-%Y"`

# // TR WS TLS
sed -i '/#trojanws$/a\### '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/trojan.json

# // TR GRPC
sed -i '/#trojangrpc$/a\### '"$user $exp"'\
},{"password": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/trojan.json

echo -e "TR $user $exp" >> /usr/local/etc/xray/user.txt

# // Link
export trojanlink1="trojan://${uuid}@${dom}:$xtls?type=ws&security=tls&path=/trojan&sni=${sni}#${user}";
export trojanlink2="trojan://${uuid}@${dom}:$none?host=${sni}&security=none&type=ws&path=/trojan-none#${user}";
export trojanlink3="trojan://${uuid}@$dom:${xtls}?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${sni}#${user}";

systemctl restart xray@trojan.service

sleep 1
clear;
echo -e "";
echo -e "=====-XRAY-TROJAN/WS&GRPC-=====";
echo -e "REMARKS   = ${user}";
echo -e "MYIP      = ${IP_NYA}";
echo -e "SUBDOMAIN = ${dom}";
echo -e "PORT TLS  = $xtls";
echo -e "PORT NONE = $none";
echo -e "PASSWORD  = ${uuid}";
echo -e "===============================";
echo -e "TROJAN WS TLS LINK";
echo -e " ${trojanlink1} ";
echo -e "";
echo -e "===============================";
echo -e "TROJAN WS LINK";
echo -e " ${trojanlink2} ";
echo -e "";
echo -e "===============================";
echo -e "TROJAN GRPC TLS LINK";
echo -e " ${trojanlink3} ";
echo -e "";
echo -e "===============================";
echo -e "EXPIRED   = $exp1";
echo -e "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu
menu
}

clear;
echo -e "";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${NC}${BG}               ⇱ TROJAN WS & GRPC ⇲             ${BLUE}│${NC}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${LIGHT}  [${GREEN}01${LIGHT}] ${RED}•${LIGHT} CREATE USER TROJAN ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}02${LIGHT}] ${RED}•${LIGHT} DELETE USER TROJAN ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}03${LIGHT}] ${RED}•${LIGHT} RENEW  USER TROJAN ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}04${LIGHT}] ${RED}•${LIGHT} CHECK  USER TROJAN ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}05${LIGHT}] ${RED}•${LIGHT} TRIAL  USER TROJAN ACCOUNT";
echo -e "${BLUE}│${NC}"
echo -e "${BLUE}│${LIGHT}  [${RED}00${LIGHT}] ${RED}• BACK TO MENU${LIGHT}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}──────────────────────────────────────────────────${NC}${LIGHT}";
echo -e"";
echo -e -n " Select menu [${GREEN} 0 - 5 ${LIGHT}] = "; read x
if [[ $x = 1 || $x = 01 ]]; then
 clear
 add-trojan
 elif [[ $x = 2 || $x = 02 ]]; then
 clear
 del-trojan
 elif [[ $x = 3 || $x = 03 ]]; then
 clear
 renew-trojan
 elif [[ $x = 4 || $x = 04 ]]; then
 clear
 cek-trojan
 elif [[ $x = 5 || $x = 05 ]]; then
 clear
 trial-trojan
 elif [[ $x = 0 || $x = 00 ]]; then
 clear
 menu
 else
   echo -e " PLEASE ENTER THE CORRECT NUMBER"
 sleep 1
  menu-trojan
 fi
