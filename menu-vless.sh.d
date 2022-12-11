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

function add-vless() {
clear
# // Port
export none="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS NTLS" | cut -d: -f2|sed 's/ //g')";
export xtls="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS TLS" | cut -d: -f2|sed 's/ //g')";

# // User
read -rp "USERNAME [ USER ]   = " -e user
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
    echo -e " USERNAME [ ${RED}$user${LIGHT} ] ALREADY USE ${NC}";
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

# VL WS TLS
sed -i '/#vless$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/vless.json

# VL GRPC
sed -i '/#vlessgrpc$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/vless.json

echo -e "VL $user $exp" >> /usr/local/etc/xray/user.txt;

# // Link
export vlesslink1="vless://${uuid}@${dom}:$xtls?path=/vless&security=tls&encryption=none&type=ws&sni=$sni#${user}";
export vlesslink2="vless://${uuid}@${dom}:$none?path=/vless-none&encryption=none&type=ws&sni=$sni#${user}";
export vlesslink3="vless://${uuid}@${dom}:${xtls}?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=$sni#$user";

systemctl restart xray@vless.service

clear;
echo -e "=======-XRAY-VLESS/WS&GRPC-=======";
echo -e "REMARKS   = ${user}";
echo -e "MYIP      = ${IP_NYA}";
echo -e "SUBDOMAIN = ${dom}";
echo -e "PORT TLS  = ${xtls}";
echo -e "PORT NONE = ${none}";
echo -e "USER ID   = ${uuid}";
echo -e "==================================";
echo -e "VLESS WS TLS LINK";
echo -e " ${vlesslink1} ";
echo -e "";
echo -e "==================================";
echo -e "VLESS WS LINK";
echo -e " ${vlesslink2} ";
echo -e "";
echo -e "==================================";
echo -e "VLESS GRPC TLS LINK";
echo -e " ${vlesslink3} ";
echo -e "";
echo -e "==================================";
echo -e "EXPIRED   = $exp1";
echo -e "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu
menu
}

function del-vless() {
clear
# // Del Vless
export NUMBER_OF_CLIENTS=$(grep -c -E "^VL " "/usr/local/etc/xray/user.txt");
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo "";
		echo -e " ${ERROR} NO USER IN VPS";
		exit 1
	fi
	echo ""; 
	echo " ====-DELETE USER VLESS-====";
	echo "     NO USER  EXPIRED";
	grep -E "^VL " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2-4 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
	echo " ===========================";
	read -rp " Select Number [1]: " CLIENT_NUMBER
	else
	echo " ===========================";
	read -rp " Select Number [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
	fi
	done
export user=$(grep -E "^VL " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p);
export exp=$(grep -E "^VL " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p);

sed -i "/\b$user\b/d" /usr/local/etc/xray/user.txt
sed -i "/^### $user $exp/,/^},{/d" /usr/local/etc/xray/vless.json
systemctl restart xray@vless.service

clear
echo "";
echo "====-USER VLESS DELETE-====";
echo " USERNAME  = $user";
echo " EXPIRED   = $exp";
echo "===========================";
echo "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU VLESS${NC}"; read  menu
menu-vless
}

function renew-vless() {
clear
# // Renew Vless
export NUMBER_OF_CLIENTS=$(grep -c -E "^VL " "/usr/local/etc/xray/user.txt");
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		clear
		echo "";
		echo -e " ${ERROR} NO USER IN VPS";
		exit 1
	fi

	clear
	echo "";
	echo -e "====-RENEW CLIENT VLESS-====";
	grep -E "^VL " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2-3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
           echo "============================";
			read -rp "Select Menu [1]: " CLIENT_NUMBER
		else
           echo "============================";
			read -rp "Select Menu [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done
        echo "";
        read -p "EXPIRED [ DAYS ] = " masaaktif

# // User && Exp
export user=$(grep -E "^VL " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p);
export exp=$(grep -E "^VL " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p);
export now=$(date +%Y-%m-%d);
export d1=$(date -d "$exp" +%s);
export d2=$(date -d "$now" +%s);
export exp2=$(( (d1 - d2) / 86400 ));
export exp3=$(($exp2 + $masaaktif));
export exp4=`date -d "$exp3 days" +"%Y-%m-%d"`

sed -i "s/VL $user $exp/VL $user $exp4/g" /usr/local/etc/xray/user.txt
sed -i "s/### $user $exp/### $user $exp4/g" /usr/local/etc/xray/vless.json

systemctl restart xray@vless.service

clear
echo "";
echo "====-CLIENT VLESS RENEW-====";
echo " USERNAME  = $user";
echo " ADDED     = $now";
echo " EXPIRED   = $exp4";
echo "============================";
echo "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU VLESS"; read  menu
menu-vless
}

function cek-vless() {
clear
# // CEK ACCOUNT
export ACC_NYA=$(grep -c -E "^VL " "/usr/local/etc/xray/user.txt")
if [[ ${ACC_NYA} == '0' ]]; then
   echo ""
   echo -e " ${ERROR} YOU DON'T HAVE A VLESS ACCOUNT !!!";
   sleep 1
   menu-vless
fi

# // CEK VLESS
echo -n > /tmp/other.txt
data=( `cat /usr/local/etc/xray/user.txt | grep 'VL' | cut -d ' ' -f 2 | sort | uniq`);
echo -e "";
echo -e " ======-VLESS USER LOGIN-======";
for akun in "${data[@]}"
do

echo -n > /tmp/ipvless.txt
data2=( `cat /var/log/xray/access.log | grep "$(date -d "0 days" +"%H:%M" )" | tail -n150 | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | sort | uniq`);
for ip in "${data2[@]}"
do

jum=$(cat /var/log/xray/access.log | grep "$(date -d "0 days" +"%H:%M" )" | grep -w $akun | tail -n150 | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | grep -F $ip | sed 's/2402//g' | sort | uniq)
if [[ "$jum" = "$ip" ]]; then
echo "$jum" >> /tmp/ipvless.txt
else
echo "$ip" >> /tmp/other.txt
fi
jum2=$(cat /tmp/ipvless.txt)
sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
done

jum=$(cat /tmp/ipvless.txt)
if [[ "$jum" = "$akun" ]]; then
echo > /dev/null
else
jum2=$(cat /tmp/ipvless.txt | nl -s " • " )
echo -e "  USER = $akun";
echo -e "$jum2";
echo -e " ==============================";
fi
rm -rf /tmp/ipvless.txt
done
rm -rf /tmp/ipvless.txt
rm -rf /tmp/other.txt
echo -e -n " PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU VLESS${NC}"; read  menu
menu-vless
}

function trial-vless() {
clear
# // Get User Ramdom
export none="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS NTLS" | cut -d: -f2|sed 's/ //g')";
export xtls="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS TLS" | cut -d: -f2|sed 's/ //g')";

export user=TRIALvless-`</dev/urandom tr -dc X-Z0-9 | head -c4`
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

# VL WS TLS
sed -i '/#vless$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/vless.json

# VL GRPC
sed -i '/#vless-grpc$/a\### '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /usr/local/etc/xray/vless.json

echo -e "VL $user $exp" >> /usr/local/etc/xray/user.txt

# // Link
export vlesslink1="vless://${uuid}@${dom}:$xtls?path=/vless&security=tls&encryption=none&type=ws&sni=$sni#${user}";
export vlesslink2="vless://${uuid}@${dom}:$none?path=/vless-none&encryption=none&type=ws&sni=$sni#${user}";
export vlesslink3="vless://${uuid}@${dom}:${xtls}?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=$sni#$user";

systemctl restart xray@vless.service

sleep 1
clear;
echo -e "";
echo -e "=====-XRAY-VLESS/WS&GRPC=====";
echo -e "REMARKS   = ${user}";
echo -e "MYIP      = ${IP_NYA}";
echo -e "SUBDOMAIN = ${dom}";
echo -e "PORT TLS  = $xtls";
echo -e "PORT NONE = $none";
echo -e "USER ID   = ${uuid}";
echo -e "=============================";
echo -e "VLESS WS TLS LINK";
echo -e " ${vlesslink1} ";
echo -e "";
echo -e "=============================";
echo -e "VLESS WS LINK";
echo -e " ${vlesslink2} ";
echo -e "";
echo -e "=============================";
echo -e "VLESS GRPC TLS LINK";
echo -e " ${vlesslink3} ";
echo -e "";
echo -e "=============================";
echo -e "EXPIRED   = $exp1";
echo -e "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu                                 
menu
}

clear;
echo -e "";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${NC}${BG}               ⇱ VLESS WS & GRPC ⇲              ${BLUE}│${NC}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${LIGHT}  [${GREEN}01${LIGHT}] ${RED}•${LIGHT} CREATE USER VLESS ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}02${LIGHT}] ${RED}•${LIGHT} DELETE USER VLESS ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}03${LIGHT}] ${RED}•${LIGHT} RENEW  USER VLESS ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}04${LIGHT}] ${RED}•${LIGHT} CHECK  USER VLESS ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}05${LIGHT}] ${RED}•${LIGHT} TRIAL  USER VLESS ACCOUNT";
echo -e "${BLUE}│${NC}"
echo -e "${BLUE}│${LIGHT}  [${RED}00${LIGHT}] ${RED}• BACK TO MENU${LIGHT}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}──────────────────────────────────────────────────${NC}${LIGHT}";
echo -e"";
echo -e -n " Select menu [${GREEN} 0 - 5 ${LIGHT}] = "; read x
if [[ $x = 1 || $x = 01 ]]; then
 clear
 add-vless
 elif [[ $x = 2 || $x = 02 ]]; then
 clear
 del-vless
 elif [[ $x = 3 || $x = 03 ]]; then
 clear
 renew-vless
 elif [[ $x = 4 || $x = 04 ]]; then
 clear
 cek-vless
 elif [[ $x = 5 || $x = 05 ]]; then
 clear
 trial-vless
 elif [[ $x = 0 || $x = 00 ]]; then
 clear
 menu
 else
   echo -e " PLEASE ENTER THE CORRECT NUMBER"
 sleep 1
  menu-vless
 fi
