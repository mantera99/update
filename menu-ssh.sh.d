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

function add-ssh() {
clear
# // Add
ssl="$(cat ~/log-install.txt | grep -w "STUNNEL4" | cut -d: -f2)";
wsnone=`cat ~/log-install.txt | grep -w "SSH WEBSOCKET NONE" | cut -d: -f2|sed 's/ //g' | cut -f1`
wstls=`cat ~/log-install.txt | grep -w "SSH WEBSOCKET TLS" | cut -d: -f2|sed 's/ //g' | cut -f1`
wsovpn=`cat ~/log-install.txt | grep -w "OVPN WEBSOCKET TLS" | cut -d: -f2|sed 's/ //g' | cut -f1`
ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
ovpn1="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

until [[ $Login =~ ^[a-zA-Z0-9_]+$ && ${CLIENT_EXISTS} == '0' ]]; do
        read -p "USERNAME [ USER ] = " Login
        CLIENT_EXISTS=$(grep -w $Login /etc/passwd | wc -l)
	if [[ ${CLIENT_EXISTS} == '1' ]]; then
        clear
        echo ""
        echo -e " USERNAME [ ${RED}$Login${LIGHT} ] ALREADY USE ";
        exit 1
     fi
done
read -p "PASSWORD [ PASS ] = " Pass
read -p "EXPIRED  [ DAYS ] = " masaaktif

# // Dom && Date && Exp
export domain=$(cat /usr/local/etc/xray/domain);
export NS_NYA=$(cat /usr/local/etc/xray/nsdomain);
export PUB_KEY=$(cat /etc/slowdns/server.pub);

# // User
useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
export exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')";
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null

echo -e "";
echo -e "${LIGHT}GENERATE USER......";
sleep 0.5
echo -e "";
echo -e "${LIGHT}GENERATE PASSWORD......";
sleep 0.5
clear;
echo -e "=========-SSHVPN-WS-=========";
echo -e "MYIP        = $IP_NYA";
echo -e "SUBDOMAIN   = ${domain}";
echo -e "DOM OVPN WS = ovpn.${domain}";
echo -e "USERNAME    = $Login";
echo -e "PASSWORD    = $Pass";
echo -e "OPENSSH     = 22";
echo -e "DROPBEAR    = 109";
echo -e "SSL/TLS     =$ssl";
echo -e "OPENVPN     = TCP ${ovpn}, UDP ${ovpn1}";
echo -e "SSH WS      = $wsnone";
echo -e "SSH WS TLS  = $wstls";
echo -e "OVPN WS TLS = $wsovpn";
echo -e "OPENVPN     = TCP http://$IP_NYA:85/client-tcp.ovpn"
echo -e "OPENVPN     = UDP http://$IP_NYA:85/client-udp.ovpn"
echo -e "BADVPN      = 7100-7900";
echo -e "====SLOW-DNS-INFORMATION-====";
echo -e "SLOW DNS PORT (PORT) = 22,80,443";
echo -e "NAME SERVER   (NS)   = ${NS_NYA}";
echo -e "PUBLIC KEY    (KEY)  = ${PUB_KEY}";
echo -e "=============================";
echo -e "PAYLOAD WS TLS";
echo -e " GET wss://SNI_BUG [protocol][crlf]Host: ${domain}[crlf]Upgrade: websocket[crlf][crlf]"
echo -e "";
echo -e "=============================";
echo -e "PAYLOAD WS NTLS";
echo -e " GET / HTTP/1.1[crlf]Host: ${domain}[crlf]Upgrade: websocket[crlf][crlf]"
echo -e "";
echo -e "=============================";
echo -e "PAYLOAD OVPN WS TLS";
echo -e " GET wss://SNI_BUG [protocol][crlf]Host: ovpn.${domain}[crlf]Upgrade: websocket[crlf][crlf]"
echo -e "";
echo -e "=============================";
echo -e "EXPIRED    = $exp";
echo -e "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU${NC} "; read  menu
menu
}

function del-ssh() {
clear
echo -e "";
read -p " USERNAME SSH TO DELETE = " Pengguna

if getent passwd $Pengguna > /dev/null 2>&1; then
        userdel $Pengguna
        clear
        echo -e "";
        echo -e " USERNAME ${GREEN}$Pengguna${LIGHT} WAS REMOVED"
else
       clear
       echo -e "";
        echo -e " USERNAME ${RED}$Pengguna${LIGHT} NOT EXIST"
fi
echo ""
echo -e -n "PRESS [${BLUE} ENTER ${LIGHT}] TO MENU${NC}"; read  menu
menu
}

function renew-ssh() {
clear
# // Renew Ssh
echo -e "";
read -p " USERNAME     =  " User

egrep "^$User" /etc/passwd >/dev/null
    if [ $? -eq 0 ]; then
    read -p " DAYS EXTEND  =  " Days

# // User && Exp
export Today=`date +%s`
#export Today=`date +"%Y-%m-%d"` 
export Days_Detailed=$(( $Days * 86400 ));
export Expire_On=$(($Today + $Days_Detailed));
export Expiration=$(date -u --date="1970-01-01 $Expire_On sec GMT" +%Y/%m/%d);
export Expiration_Display=$(date -u --date="1970-01-01 $Expire_On sec GMT" '+%d %b %Y');

passwd -u $User
usermod -e  $Expiration $User
egrep "^$User" /etc/passwd >/dev/null
echo -e "$Pass\n$Pass\n"|passwd $User &> /dev/null

clear
echo "";
echo "====-CLIENT SSH WS RENEW-========";
echo " USERNAME  = $User";
echo " ADDED     = $Days Days";
echo " EXPIRED   = $Expiration_Display";
echo "=================================";
echo "";
else
clear;

echo -e "======================================";

echo -e "        USERNAME DOESNT EXIT       ";

echo -e "======================================";
fi
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU SSH${NC}"; read  menu                                 
menu-ssh
}

function cek-ssh() {
clear
# // Cek Ssh
if [ -e "/var/log/auth.log" ]; then
        LOG="/var/log/auth.log";
fi
if [ -e "/var/log/secure" ]; then
        LOG="/var/log/secure";
fi

data=( `ps aux | grep -i dropbear | awk '{print $2}'`);
echo
echo "==========-[ DROPBEAR USER LOGIN ]-===========";
echo "  ID  |  USERNAME  |  IP ADDRESS";
echo "==============================================";
cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/login-db.txt;
for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "dropbear\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $10}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $12}'`;
        if [ $NUM -eq 1 ]; then
                echo " $PID - $USER - $IP";
                fi
done

echo
echo "==========-[ OPENSSH USER LOGIN ]-============";
echo "  ID  |  USERNAME  |  IP ADDRESS";
echo "==============================================";
cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/login-db.txt
data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);

for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "sshd\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $9}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $11}'`;
        if [ $NUM -eq 1 ]; then
                echo "$PID - $USER - $IP";
        fi
done

if [ -f "/etc/openvpn/server/openvpn-tcp.log" ]; then
        echo " "
        echo "========-[ OPENVPN TCP USER LOGIN ]-==========";
        echo "  USERNAME  |  IP ADDRESS  |  CONNECTED";
        echo "==============================================";
        cat /etc/openvpn/server/openvpn-tcp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-tcp.txt
        cat /tmp/vpn-login-tcp.txt
fi

if [ -f "/etc/openvpn/server/openvpn-udp.log" ]; then
        echo " "
        echo "========-[ OPENVPN UDP USER LOGIN ]-==========";
        echo "  USERNAME  |  IP ADDRESS  |  CONNECTED";
        echo "==============================================";
        cat /etc/openvpn/server/openvpn-udp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-udp.txt
        cat /tmp/vpn-login-udp.txt
fi
echo "==============================================";
echo "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU SSH${NC}"; read  menu
menu-ssh
}

function trial-ssh() {
clear
# // Add
ssl="$(cat ~/log-install.txt | grep -w "STUNNEL4" | cut -d: -f2)";
wsnone=`cat ~/log-install.txt | grep -w "SSH WEBSOCKET NONE" | cut -d: -f2|sed 's/ //g' | cut -f1`
wstls=`cat ~/log-install.txt | grep -w "SSH WEBSOCKET TLS" | cut -d: -f2|sed 's/ //g' | cut -f1`
wsovpn=`cat ~/log-install.txt | grep -w "SSH WEBSOCKET TLS" | cut -d: -f2|sed 's/ //g' | cut -f1`
ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
ovpn1="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

Login=TRIALssh`</dev/urandom tr -dc X-Z0-9 | head -c4`
hari="1"
Pass=1

# // DOMAIN
export domain=$(cat /usr/local/etc/xray/domain);
export NS_NYA=$(cat /usr/local/etc/xray/nsdomain);
export PUB_KEY=$(cat /etc/slowdns/server.pub);

useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null

echo -e "";
echo -e "${LIGHT}GENERATE USER......";
sleep 1.5
echo -e "";
echo -e "${LIGHT}GENERATE PASSWORD......";
sleep 1.5
clear;
echo -e "";
echo -e "=========-SSHVPN-WS-=========";
echo -e "MYIP        = $IP_NYA";
echo -e "SUBDOMAIN   = ${domain}";
echo -e "DOM OVPN WS = ovpn.${domain}";
echo -e "USERNAME    = $Login";
echo -e "PASSWORD    = $Pass";
echo -e "OPENSSH     = 22";
echo -e "DROPBEAR    = 109";
echo -e "SSL/TLS     =$ssl";
echo -e "OPENVPN     = TCP ${ovpn}, UDP ${ovpn1}";
echo -e "SSH WS      = $wsnone";
echo -e "SSH WS TLS  = $wstls";
echo -e "OVPN WS TLS = $wsovpn";
echo -e "OPENVPN     = TCP http://$IP_NYA:85/client-tcp.ovpn"
echo -e "OPENVPN     = UDP http://$IP_NYA:85/client-udp.ovpn"
echo -e "BADVPN      = 7100-7900";
echo -e "====SLOW-DNS-INFORMATION-====";
echo -e "SLOW DNS PORT (PORT) = 22,80,443";
echo -e "NAME SERVER   (NS)   = ${NS_NYA}";
echo -e "PUBLIC KEY    (KEY)  = ${PUB_KEY}";
echo -e "=============================";
echo -e "PAYLOAD WS TLS";
echo -e " GET wss://SNI_BUG [protocol][crlf]Host: ${domain}[crlf]Upgrade: websocket[crlf][crlf]"
echo -e "";
echo -e "=============================";
echo -e "PAYLOAD WS NTLS";
echo -e " GET / HTTP/1.1[crlf]Host: ${domain}[crlf]Upgrade: websocket[crlf][crlf]"
echo -e "";
echo -e "=============================";
echo -e "PAYLOAD OVPN WS TLS";
echo -e " GET wss://SNI_BUG [protocol][crlf]Host: ovpn.${domain}[crlf]Upgrade: websocket[crlf][crlf]"
echo -e "";
echo -e "=============================";
echo -e "EXPIRED    = $exp";
echo -e "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu
menu
}

function member-ssh() {
clear
echo 
echo "---------------------------------------------------"
echo "USERNAME          EXP DATE          STATUS"
echo "---------------------------------------------------"
while read expired
do
AKUN="$(echo $expired | cut -d: -f1)"
ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
status="$(passwd -S $AKUN | awk '{print $2}' )"
if [[ $ID -ge 1000 ]]; then
if [[ "$status" = "L" ]]; then
printf "%-17s %2s %-17s %2s \n" "$AKUN" "$exp     " "LOCKED"
else
printf "%-17s %2s %-17s %2s \n" "$AKUN" "$exp     " "UNLOCKED"
fi
fi
done < /etc/passwd
JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
echo "---------------------------------------------------"
echo "ACCOUNT = $JUMLAH user"
echo "---------------------------------------------------"
echo -e "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu
menu
}

function cek-lim() {
clear
echo -e "";
echo -e "===========================================";
echo -e "         • USER MULTI LOGIN SSH •       "
echo -e "===========================================";
echo " ";
if [ -e "/root/log-limit.txt" ]; then
echo "USER WHO VIOLATE THE MAXIMUM LIMIT";
echo "TIME - USERNAME - NUMBER OF MULTILOGIN"
echo -e "===========================================";
cat /root/log-limit.txt
else
echo " NO USER HAS COMMITTED A VIOLATION"
echo " "
echo " or"
echo " "
echo " THE USER LIMIT SCRIPT NOTBEEN EXECUTED"
fi
echo " ";
echo -e "===========================================";
echo " ";
echo ""
echo -e -n "PRESS [${BLUE} ENTER ${LIGHT}] TO MENU${NC}"; read  menu
menu
}

function auto-kill() {
clear
# // Cek Status
cek=$(grep -c -E "^# Autokill" /etc/cron.d/tendang)
if [[ "$cek" = "1" ]]; then
   sts="${ONN}"
else
   sts="${OF}"
fi

clear;
echo -e "";
echo -e "=========-MENU AUTOKILL-========="
echo -e "         Status =" $sts
echo -e "[•1] AUTOKILL AFTER 5  MINUTES"
echo -e "[•2] AUTOKILL AFTER 10 MINUTES"
echo -e "[•3] AUTOKILL AFTER 15 MINUTES"
echo -e "[•4] TURN OFF AUTOKILL"
echo -e ""
echo -e "[•0] \e[31mEXIT\e[37m"
echo -e ""
echo -e "================================="                                                                                                          
echo -e ""
read -p " Select menu :  " AutoKill
echo -e ""
case $AutoKill in
                1)
                echo -e ""
                read -p " MULTILOGIN MAXIMUM NUMBER OF ALLOW = " max
                sleep 1
                clear
                echo > /etc/cron.d/tendang
                echo "# Autokill" >>/etc/cron.d/tendang
                echo "*/5 * * * *  root /usr/bin/tendang $max" >>/etc/cron.d/tendang
                echo -e "================================="                                                                                                          
                
                echo -e "  ALLOWED MULTILOGIN = $max"
                echo -e "  AUTOKILL EVERY = 5 MINUTES"      
                
                echo -e "================================="
                echo -e -n "PRESS [ \e[32mENTER\e[37m ] TO MENU SSH "; read menu
                menu-ssh                                                                                                                   
                ;;
                2)
                echo -e ""
                read -p " MULTILOGIN MAXIMUM NUMBER OF ALLOWED = " max
                sleep 1
                clear
                echo > /etc/cron.d/tendang
                echo "# Autokill" >>/etc/cron.d/tendang
                echo "*/10 * * * *  root /usr/bin/tendang $max" >>/etc/cron.d/tendang
                echo -e "================================="
                
                echo -e "  ALLOWED MULTILOGIN = $max"
                echo -e "  AUTOKILL EVERY = 10 MINUTES"
                
                echo -e "================================="
                echo -e -n "PRESS [ \e[32mENTER\e[37m ] TO MENU SSH "; read menu
                menu-ssh  
                ;;
                3)
                echo -e ""
                read -p " MULTILOGIN MAXIMUM NUMBER OF ALLOWED =" max
                sleep 1
                clear
                echo > /etc/cron.d/tendang
                echo "# Autokill" >>/etc/cron.d/tendang
                echo "*/15 * * * *  root /usr/bin/tendang $max" >>/etc/cron.d/tendang
                echo -e "================================="
                
                echo -e "  ALLOWED MULTILOGIN = $max"
                echo -e "  AUTOKILL EVERY = 15 MINUTES"
                
                echo -e "================================="
                echo -e -n "PRESS [ \e[32mENTER\e[37m ] TO MENU SSH "; read menu
                menu-ssh 
                ;;
                4)
                clear
                echo > /etc/cron.d/tendang
                echo -e "================================="
                
                echo -e "  AUTOKILL MULTILOGIN TURN OFF  "
                
                echo -e "================================="
                echo -e -n "PRESS [ \e[32mENTER\e[37m ] TO MENU SSH "; read menu
                menu-ssh 
                ;;
                0)
                exit
                ;;
        esac
}

clear;
echo -e "";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${NC}${BG}               ⇱ SSH & OVPN MENU ⇲              ${BLUE}│${NC}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${LIGHT}  [${GREEN}01${LIGHT}] ${RED}•${LIGHT} CREATE USER SSH & OVPN ";
echo -e "${BLUE}│${LIGHT}  [${GREEN}02${LIGHT}] ${RED}•${LIGHT} DELETE USER SSH & OVPN ";
echo -e "${BLUE}│${LIGHT}  [${GREEN}03${LIGHT}] ${RED}•${LIGHT} RENEW  USER SSH & OVPN ";
echo -e "${BLUE}│${LIGHT}  [${GREEN}04${LIGHT}] ${RED}•${LIGHT} CHECK  USER SSH & OVPN ";
echo -e "${BLUE}│${LIGHT}  [${GREEN}05${LIGHT}] ${RED}•${LIGHT} TRIAL  USER SSH & OVPN ";
echo -e "${BLUE}│${LIGHT}  [${GREEN}06${LIGHT}] ${RED}•${LIGHT} MEMBER SSH & OVPN ";
echo -e "${BLUE}│${LIGHT}  [${GREEN}07${LIGHT}] ${RED}•${LIGHT} CHECK  USER MULTI LOGIN SSH ";
echo -e "${BLUE}│${LIGHT}  [${GREEN}08${LIGHT}] ${RED}•${LIGHT} AUTOKILL MULTILOGIN ";
echo -e "${BLUE}│${NC}";
echo -e "${BLUE}│${LIGHT}  [${RED}00${LIGHT}] ${RED}• BACK TO MENU${NC}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}──────────────────────────────────────────────────${LIGHT}";
echo -e "";
echo -e -n " Select menu [${GREEN} 0 - 8 ${LIGHT}] = "; read x
if [[ $x = 1 || $x = 01 ]]; then
 clear
 add-ssh
 elif [[ $x = 2 || $x = 02 ]]; then
 clear
 del-ssh
 elif [[ $x = 3 || $x = 03 ]]; then
 clear
 renew-ssh
 elif [[ $x = 4 || $x = 04 ]]; then
 clear
 cek-ssh
 elif [[ $x = 5 || $x = 05 ]]; then
 clear
 trial-ssh
 elif [[ $x = 6 || $x = 06 ]]; then
 clear
 member-ssh
 elif [[ $x = 7 || $x = 07 ]]; then
 clear
 cek-lim
 elif [[ $x = 8 || $x = 08 ]]; then
 clear
 auto-kill
 elif [[ $x = 0 || $x = 00 ]]; then
 clear
 menu
 else
 echo -e " PLEASE ENTER THE CORRECT NUMBER"
 sleep 1
 menu-ssh
fi
