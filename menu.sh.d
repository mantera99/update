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
export CYAN='\033[0;36m';
export LIGHT='\033[0;37m';
export BG='\e[30;5;47m'
export NC='\033[0m';

# // Export Banner Status Information
export ERROR="${LIGHT}[${RED} ERROR ${LIGHT}]";
export INFO="[${YELLOW} INFO ${NC}]";
export OKEY="${LIGHT}[${GREEN} OKEY ${LIGHT}]";
export OKEYY="${LIGHT}[${GREEN} INFO ${LIGHT}]";

# // Exporting maklumat rangkaian
source /root/ip-detail.txt;
export IP_NYA="$IP";
export ASN_NYA="$ASN";
export REGIONNAME_NYA="$REGIONAME";
export COUNTRY_NYA="$COUNTRY";
export DOM_NYA=$(cat /usr/local/etc/xray/domain);

# // Getting
export IZIN=$(curl -sS https://raw.githubusercontent.com/Manpokr/mon/main/ip | awk '{print $4}' | grep $IP_NYA )
if [[ $IP_NYA = $IZIN ]]; then > /dev/null 2>&1;
     SKIP=true;
else
     MAN_NYA="${ERROR} PERMISION DENIED";
     rm -f setup.sh;
fi

# // Check Date Script
export SER_NYA=$( curl -sS https://raw.githubusercontent.com/Manpokr/mon/main/versi.sh)
export EXP=$(curl -sS https://raw.githubusercontent.com/Manpokr/mon/main/ip | grep $IP_NYA | awk '{print $3}')
export NAME_NYA=$(curl -sS https://raw.githubusercontent.com/Manpokr/mon/main/ip | grep $IP_NYA | awk '{print $2}')
export DAY=$(date -d +1day +%Y-%m-%d)

# // SC EXP
export waktu_sekarang=$(date -d "0 days" +"%Y-%m-%d");
export now_in_s=$(date -d "$waktu_sekarang" +%s);
export exp_in_s=$(date -d "$EXP" +%s);
export days_left=$(( ($exp_in_s - $now_in_s) / 86400 ));

echo $EXP > /root/expired.txt;
  while read expired
  do
export EXP1=$(echo $EXP | curl -sS https://raw.githubusercontent.com/Manpokr/mon/main/ip | grep $IP_NYA | awk '{print $3}')
if [[ $EXP1 < $DAY ]]; then > /dev/null 2>&1;
   EXP_NYA="${RED}Expired${NC} ${GREEN}Date${NC}";
else
if [[ $EXP1 == "Lifetime" ]]; then
   EXP_NYA="${GREEN}Lifetime Days${NC}";
   LIP_NYA=Lifetime
else
   EXP_NYA="${GREEN}$days_left Days${NC}";
   LIP_NYA=Lifetime
fi
fi
done < /root/expired.txt;
rm /root/expired.txt;

# // Status certificate
export modifyTime=$(stat $HOME/.acme.sh/${DOM_NYA}_ecc/${DOM_NYA}.key | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}');
export modifyTime1=$(date +%s -d "${modifyTime}");
export currentTime=$(date +%s);
export stampDiff=$(expr ${currentTime} - ${modifyTime1});
export days=$(expr ${stampDiff} / 86400);
export remainingDays=$(expr 90 - ${days});
export TLS_NYA="${remainingDays} Days";

# // Status Cert
if [[ ${remainingDays} -le 0 ]]; then
   TLS_NYA="${RED}Expired${NC} ${GREEN}Date${LIGHT}";
fi

# // Download/Upload today
export uptime="$(uptime -p | cut -d " " -f 2-10)";

# // Getting CPU Information
source /home/version;
export VER_NYA="$VERSION";
export TELE_NYA="$TELE";
export JAM=$(date +%r);
export DAY=$(date +%A);
export DATE=$(date +%d.%m.%Y);

# // Getting OS Information
source /etc/os-release;
export VER_OS=$VERSION
export VER=$VERSION_ID
export TIPE=$NAME
export URL_SUPPORT=$HOME_URL
export BAS=$ID

# // Ram
export uram=$( free -m | awk 'NR==2 {print $3}' );
export totalcore="$(grep -c "^processor" /proc/cpuinfo)";
export totalcore+=" Core";

# Getting CPU Information
export cpu_usage1="$(ps aux | awk 'BEGIN {sum=0} {sum+=$3}; END {print sum}')";
export cpu_usage="$((${cpu_usage1/\.*} / ${corediilik:-1}))";
export cpu_usage+=" %";
export shellversion+=" ${BASH_VERSION/-*}"
export versibash=$shellversion

# // Ver Xray & V2ray
export XVER_NYA="$(/usr/local/bin/xray -version | awk NR==1 | cut -d " " -f 1-2 )";
export ISA_NYA=$(curl -sS https://raw.githubusercontent.com/Manpokr/mon/main/ip | grep $IP_NYA | awk '{print $5}')

# // STATUS XRAY
xray_ws=$( systemctl status xray | grep Active | awk '{print $3}' | sed 's/(//g' | sed 's/)//g' )
if [[ $xray_ws == "running" ]]; then
    XRAY="${GREEN}ON${LIGHT}"
else
    XRAY="${RED}OFF${LIGHT}"
fi

# // STATUS NGINX
nginx_ws=$( systemctl status nginx | grep Active | awk '{print $3}' | sed 's/(//g' | sed 's/)//g' )
if [[ $nginx_ws == "running" ]]; then
    NGINX="${GREEN}ON${LIGHT}"
else
    NGINX="${RED}OFF${LIGHT}"
fi

# // STATUS SSHWS
ssh_ws=$( systemctl status ws-stunnel | grep Active | awk '{print $3}' | sed 's/(//g' | sed 's/)//g' )
if [[ $ssh_ws == "running" ]]; then
    SSH="${GREEN}ON${LIGHT}"
else
    SSH="${RED}OFF${LIGHT}"
fi

# // Check Update
clear;
if [[ ${SER_NYA} = ${VER_NYA} ]]; then
   SKIP=true;
else
echo -e "${LIGHT}";
echo -e "   -----------------------------------------------
       ${OKEYY} UPDATE AVAILABLE VERSION = ${GREEN}V${LIGHT}${RED}${SER_NYA}${LIGHT}
           DO YOU WANT TO UPDATE ? (y/n)?
   -----------------------------------------------${LIGHT}"
echo -e -n "   Input [${GREEN} (y/n) ${LIGHT}] To Continue = "; read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then > /dev/null 2>&1;
    SKIP=true;
    else
    menu-update
fi
fi

# // USER
ref_nya(){
if [ "${ISA_NYA}" = "ON" ];
   then
   echo -e "${LIGHT} USER ROLES              =${NC}  Premium User";
else
   echo -e "${LIGHT} USER ROLES              =${NC}  ${RED}Premium Version${NC}";
fi
}

# // MENU REG
reg_nya(){
if [ "${ISA_NYA}" = "ON" ];
   then
   RESS_NYA="menu"
   echo -e "${BLUE}│${LIGHT} [${GREEN}08${LIGHT}] ${RED}•${LIGHT} EXIT ${NC}";
else
   echo -e "${BLUE}│${LIGHT} [${GREEN}08${LIGHT}] ${RED}•${LIGHT} EXIT              [${GREEN}10${LIGHT}] ${RED}•${LIGHT} REG IP ${NC}";
   RESS_NYA="menu-ip"
fi
}

# // Status
vl=$(cat /usr/local/etc/xray/user.txt | grep "^VL " | wc -l);
vm=$(cat /usr/local/etc/xray/user.txt | grep "^VM " | wc -l);
xtls=$(cat /usr/local/etc/xray/user.txt | grep "^XTLS " | wc -l);
tr=$(cat /usr/local/etc/xray/user.txt | grep "^TR " | wc -l);
ss=$(cat /usr/local/etc/xray/user.txt | grep "^SS " | wc -l);
ssh="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"

clear;
echo -e "";
echo -e "${BLUE}┌─────────────────────────────────────────────────┐${NC}";
echo -e "${BLUE}│${NC}${BG}                 ⇱ SCRIPT MENU ⇲                 ${BLUE}│${NC}";
echo -e "${BLUE}└─────────────────────────────────────────────────┘${NC}";
echo -e "${LIGHT} OS NAME                 =${NC}  $TIPE";
echo -e "${LIGHT} ISP NAME                =${NC}  $ASN_NYA";
echo -e "${LIGHT} CITY                    =${NC}  $COUNTRY_NYA";
echo -e "${LIGHT} REGION NAME             =${NC}  $REGIONNAME_NYA";
echo -e "${LIGHT} DOMAIN                  =${NC}  $DOM_NYA";
echo -e "${LIGHT} MYIP                    =${NC}  $IP_NYA";
echo -e "${LIGHT} TIME                    =${NC}  $JAM";
echo -e "${LIGHT} DAY                     =${NC}  $DAY";
echo -e "${LIGHT} DATE                    =${NC}  $DATE";
echo -e "${LIGHT} PROC CORE               =${NC}  $totalcore";
echo -e "${LIGHT} CPU USED                =${NC}  $cpu_usage";
echo -e "${LIGHT} USED RAM                =${NC}  ${RED}$uram${LIGHT} MB";
echo -e "${LIGHT} TELEGRAM                =${NC}  $TELE_NYA";
echo -e "${LIGHT} XRAY CORE               =${NC}  $XVER_NYA Version";
echo -e "${LIGHT} SCRIPT                  =${NC}  $VER_NYA Version";
echo -e "${LIGHT} CERT EXPIRED ON         =${NC}  ${TLS_NYA}";
ref_nya
echo -e "${LIGHT} CLIENT NAME             =${NC}  $NAME_NYA";
echo -e "${LIGHT} SCRIPT EXPIRED ON       =${NC}  $EXP_NYA";
echo -e "${BLUE}┌─────────────────────────────────────────────────┐${NC}";
echo -e "${BLUE}│${LIGHT}  [ SSH WS = $SSH ]  [ XRAY = $XRAY ]  [ NGINX = $NGINX ]" 
echo -e "${BLUE}└─────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌─────────────────────────────────────────────────┐${NC}";
echo -e "${BLUE}│${LIGHT}VLESS    VMESS    TROJAN    S-SOCK    XTLS    SSH"
echo -e "${BLUE}│${GREEN}  $vl        $vm         $tr         $ss       $xtls       $ssh${NC}"
echo -e "${BLUE}└─────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌─────────────────────────────────────────────────┐${NC}";
echo -e "${BLUE}│${LIGHT} [${GREEN}01${LIGHT}] ${RED}•${LIGHT} SSHVPN WS         [${GREEN}04${LIGHT}] ${RED}•${LIGHT} TROJAN WS&GRPC${NC}";
echo -e "${BLUE}│${LIGHT} [${GREEN}02${LIGHT}] ${RED}•${LIGHT} VLESS WS&GRPC     [${GREEN}05${LIGHT}] ${RED}•${LIGHT} SHDWSCK22 WS&GRPC${NC}";
echo -e "${BLUE}│${LIGHT} [${GREEN}03${LIGHT}] ${RED}•${LIGHT} VMESS WS&GRPC     [${GREEN}06${LIGHT}] ${RED}•${LIGHT} XRAY TCP&XTLS${NC}";
echo -e "${BLUE}│${NC}";
echo -e "${BLUE}│${LIGHT} [${GREEN}07${LIGHT}] ${RED}•${LIGHT} SYSTEM MENU       [${GREEN}09${LIGHT}] ${RED}•${LIGHT} STATUS SERVICE${NC}";
reg_nya
echo -e "${BLUE}└─────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌─────────────────────────────────────────────────┐${NC}";
echo -e "${BLUE}│${NC}${BG}             ⇱ MANTERNETVPN PROJECT ⇲            ${BLUE}│${NC}";
echo -e "${BLUE}└─────────────────────────────────────────────────┘${NC}";
echo -e "            $MAN_NYA${LIGHT}";
echo -e -n " Select menu [${GREEN} 0 - 10 ${LIGHT}] = "; read x
if [[ ${LIP_NYA} = "Lifetime" ]] > /dev/null 2>&1;
 then
 if [[ $x = 1 || $x = 01 ]]; then
 clear
 menu-ssh
 elif [[ $x = 2 || $x = 02 ]]; then
 clear
 menu-vless
 elif [[ $x = 3 || $x = 03 ]]; then
 clear
 menu-vmess
 elif [[ $x = 4 || $x = 04 ]]; then
 clear
 menu-trojan
 elif [[ $x = 5 || $x = 05 ]]; then
 clear
 menu-ss
 elif [[ $x = 6 || $x = 06 ]]; then
 clear
 menu-xtls
 elif [[ $x = 7 || $x = 07 ]]; then
 clear
 menu-system
 elif [[ $x = 8 || $x = 08 ]]; then
 exit
 elif [[ $x = 9 || $x = 09 ]]; then
 clear
 status
 elif [[ $x = 10 ]]; then
 clear
 ${RESS_NYA}
else
    echo -e " PLEASE ENTER THE CORRECT NUMBER"
    sleep 1
    menu
fi
fi
