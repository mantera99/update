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

function add-ss() {
clear
# // Add
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
    echo -e " USERNAME [ \e[31m$user\e[37m ] ALREADY USE ";
    exit 1;
fi

# // Date && Bug
read -p "EXPIRED [ DAY ]     = " masaaktif
read -p "SNI [ BUG ]         = " sni
read -p "SUBDOMAIN [ WILCD ] = " sub

# // Domain && Uuid
export domain=$(cat /usr/local/etc/xray/domain);
export dom=$sub$domain
export PWDR_NYA=$(cat /usr/local/etc/xray/passwd)
export PWD_NYA=$(openssl rand -base64 16)

# // Date && Exp
export hariini=`date -d "0 days" +"%Y-%m-%d"` 
export exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
export exp1=`date -d "$masaaktif days" +"%d-%m-%Y"`

# // Json
cat <<EOF >>"/home/vps/public_html/${user}-none"
{
  "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": false
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$dom",
            "level": 8,
            "method": "2022-blake3-aes-128-gcm",
            "password": "$PWDR_NYA:$PWD_NYA",
            "port": $none,
            "uot": true
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "headers": {
            "Host": "$sni"
          },
          "path": "/ss-none"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
EOF

cat <<EOF >>"/home/vps/public_html/${user}-tls"
{ 
 "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$dom",
            "level": 8,
            "method": "2022-blake3-aes-128-gcm",
            "password": "$PWDR_NYA:$PWD_NYA",
            "port": $xtls
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": "$dom"
        },
        "wsSettings": {
          "headers": {
            "Host": "$sni"
          },
          "path": "/ss-ws"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
EOF

cat <<EOF >>"/home/vps/public_html/${user}-grpc"
{
    "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$dom",
            "level": 8,
            "method": "2022-blake3-aes-128-gcm",
            "password": "$PWDR_NYA:$PWD_NYA",
            "port": $xtls
          }
        ]
      },
      "streamSettings": {
        "grpcSettings": {
          "multiMode": true,
          "serviceName": "ss-grpc"
        },
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": "$sni"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
EOF

# // Link
export link="http://${IP_NYA}:85/${user}-tls";
export link0="http://${IP_NYA}:85/${user}-none";
export link1="http://${IP_NYA}:85/${user}-grpc";

# // SS WS TLS
sed -i '/#ssws$/a\### '"$user $exp"'\
},{"password": "'""$PWD_NYA""'","email": "'""$user""'"' /usr/local/etc/xray/ss.json

# // SS GRPC TLS
sed -i '/#ssgrpc$/a\### '"$user $exp"'\
},{"password": "'""$PWD_NYA""'","email": "'""$user""'"' /usr/local/etc/xray/ss.json

echo -e "SS $user $exp" >> /usr/local/etc/xray/user.txt

systemctl restart xray@ss.service

clear;
echo -e "======-XRAY-SS/WS&GRPC-=======";
echo -e "REMARKS   = ${user}";
echo -e "MYIP      = ${IP_NYA}";
echo -e "SUBDOMAIN = ${dom}";
echo -e "PORT TLS  = ${xtls}";
echo -e "PORT NONE = ${none}";
echo -e "USER ID   = ${PWDR_NYA}:${PWD_NYA}";
echo -e "METHOD    = 2022-blake3-aes-128-gcm";
echo -e "==============================";
echo -e "IMPORT LINK KE CUSTOM GatchaNG";
echo -e "==============================";
echo -e "JSON SHADOWSOCK WS TLS LINK";
echo -e " ${link} ";
echo -e "";
echo -e "==============================";
echo -e "JSON SHADOWSOCK WS LINK";
echo -e " ${link0} ";
echo -e "";
echo -e "==============================";
echo -e "JSON SHADOWSOCK GRPC TLS LINK";
echo -e " ${link1}";
echo -e "";
echo -e "==============================";
echo -e "EXPIRED    = $exp1";
echo -e "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu
menu
}

function del-ss() {
clear
# // Del Vless
export NUMBER_OF_CLIENTS=$(grep -c -E "^SS " "/usr/local/etc/xray/user.txt");
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo "";
		echo -e " ${ERROR} NO USER IN VPS";
		exit 1
	fi
	echo "";
	echo " ====-DELETE USER SHDWSOCK-====";
	echo "     NO USER  EXPIRED";
	grep -E "^SS " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2-4 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
	echo " ==============================";
	read -rp " Select Number [1]: " CLIENT_NUMBER
	else
	echo " ==============================";
	read -rp " Select Number [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
	fi
	done
export user=$(grep -E "^SS " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p);
export exp=$(grep -E "^SS " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p);

sed -i "/\b$user\b/d" /usr/local/etc/xray/user.txt
sed -i "/^### $user $exp/,/^},{/d" /usr/local/etc/xray/ss.json
rm -f /home/vps/public_html/$user-tls
rm -f /home/vps/public_html/$user-grpc
rm -f /home/vps/public_html/$user-none

systemctl restart xray@ss.service

clear
echo "";
echo "====-USER SHDWSOCK DELETE-====";
echo " USERNAME  = $user";
echo " EXPIRED   = $exp";
echo "==============================";
echo "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU SHDWSOCK${NC}"; read  menu
menu-ss
}

function renew-ss() {
clear
# // Renew Ss
export NUMBER_OF_CLIENTS=$(grep -c -E "^SS " "/usr/local/etc/xray/user.txt");
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		clear
		echo "";
		echo -e " ${ERROR} NO USER IN VPS";
		exit 1
	fi

	clear
	echo "";
	echo -e "====-RENEW CLIENT SHADOWSOCK-====";
	grep -E "^SS " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2-3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
           echo "=================================";
			read -rp "Select Menu [1]: " CLIENT_NUMBER
		else
           echo "=================================";
			read -rp "Select Menu [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done
        echo "";
        read -p " EXPIRED [ DAYS ] = " masaaktif

# // User && Exp
export user=$(grep -E "^SS " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p);
export exp=$(grep -E "^SS " "/usr/local/etc/xray/user.txt" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p);
export now=$(date +%Y-%m-%d);
export d1=$(date -d "$exp" +%s);
export d2=$(date -d "$now" +%s);
export exp2=$(( (d1 - d2) / 86400 ));
export exp3=$(($exp2 + $masaaktif));
export exp4=`date -d "$exp3 days" +"%Y-%m-%d"`

# // User
sed -i "s/SS $user $exp/SS $user $exp4/g" /usr/local/etc/xray/user.txt
sed -i "s/### $user $exp/### $user $exp4/g" /usr/local/etc/xray/ss.json

systemctl restart xray@ss.service

clear
echo "";
echo "====-CLIENT SHADOWSOCK RENEW-====";
echo " USERNAME  = $user";
echo " ADDED     = $now";
echo " EXPIRED   = $exp4";
echo "=================================";
echo "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU SHDWSOCK${NC} "; read  menu
menu-ss
}

function cek-ss() {
clear
# // CEK ACCOUNT
export ACC_NYA=$(grep -c -E "^SS " "/usr/local/etc/xray/user.txt")
if [[ ${ACC_NYA} == '0' ]]; then
   echo ""
   echo -e " ${ERROR} YOU DON'T HAVE A SHDWSOCK ACCOUNT !!!";
   sleep 1
   menu-ss
fi

# // CEK S-SOCK
echo -n > /tmp/other.txt
data=( `cat /usr/local/etc/xray/user.txt | grep 'SS' | cut -d ' ' -f 2 | sort | uniq`);
echo -e "";
echo -e " ======-SHDOWSOCK USER LOGIN-======";
for akun in "${data[@]}"
do
echo -n > /tmp/ipshadow.txt
data2=( `cat /var/log/xray/access.log | grep "$(date -d "0 days" +"%H:%M" )" | tail -n150 | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | sort | uniq`);
for ip in "${data2[@]}"
do

jum=$(cat /var/log/xray/access.log | grep "$(date -d "0 days" +"%H:%M" )" | grep -w $akun | tail -n150 | cut -d " " -f 3 | sed 's/tcp://g' | cut -d ":" -f 1 | grep -F $ip | sed 's/2402//g' | sort | uniq)
if [[ "$jum" = "$ip" ]]; then
echo "$jum" >> /tmp/ipshadow.txt
else
echo "$ip" >> /tmp/other.txt
fi
jum2=$(cat /tmp/ipshadow.txt)
sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
done

jum=$(cat /tmp/ipshadow.txt)
if [[ "$jum" = "$akun" ]]; then
echo > /dev/null
else
jum2=$(cat /tmp/ipshadow.txt | nl -s ' • ')
echo -e "  USER = $akun";
echo -e "$jum2";
echo -e " ==================================";
fi
rm -rf /tmp/ipshadow.txt
done
rm -rf /tmp/ipshadow.txt
rm -rf /tmp/other.txt
echo -e -n " PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU SHADOWSOCK${NC}"; read  menu
menu-ss
}

function trial-ss() {
clear
# // Add
none="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS NTLS" | cut -d: -f2|sed 's/ //g')";
xtls="$(cat ~/log-install.txt | grep -w "XRAY VLESS WS TLS" | cut -d: -f2|sed 's/ //g')";

# // Get User Ramdom
export user=TRIALss-`</dev/urandom tr -dc X-Z0-9 | head -c4`
export exp=1

read -p "SNI [ BUG ]         = " sni
read -p "SUBDOMAIN [ WILCD ] = " sub

# // Domain && Uuid
export domain=$(cat /usr/local/etc/xray/domain);
export dom=$sub$domain
export PWDR_NYA=$(cat /usr/local/etc/xray/passwd)
export PWD_NYA=$(openssl rand -base64 16)

# // Date && Exp
export hariini=`date -d "0 days" +"%Y-%m-%d"`
export exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
export exp1=`date -d "$masaaktif days" +"%d-%m-%Y"`

cat <<EOF >>"/home/vps/public_html/${user}-none"
{
  "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": false
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$dom",
            "level": 8,
            "method": "2022-blake3-aes-128-gcm",
            "password": "$PWDR_NYA:$PWD_NYA",
            "port": $none,
            "uot": true
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "headers": {
            "Host": "$sni"
          },
          "path": "/ss-none"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
EOF

cat <<EOF >>"/home/vps/public_html/${user}-tls"
{ 
 "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$dom",
            "level": 8,
            "method": "2022-blake3-aes-128-gcm",
            "password": "$PWDR_NYA:$PWD_NYA",
            "port": $xtls
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": "$dom"
        },
        "wsSettings": {
          "headers": {
            "Host": "$sni"
          },
          "path": "/ss-ws"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
EOF

cat <<EOF >>"/home/vps/public_html/${user}-grpc"
{
    "dns": {
    "servers": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  },
 "inbounds": [
   {
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true,
        "userLevel": 8
      },
      "sniffing": {
        "destOverride": [
          "http",
          "tls"
        ],
        "enabled": true
      },
      "tag": "socks"
    },
    {
      "port": 10809,
      "protocol": "http",
      "settings": {
        "userLevel": 8
      },
      "tag": "http"
    }
  ],
  "log": {
    "loglevel": "none"
  },
  "outbounds": [
    {
      "mux": {
        "enabled": true
      },
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "$dom",
            "level": 8,
            "method": "2022-blake3-aes-128-gcm",
            "password": "$PWDR_NYA:$PWD_NYA",
            "port": $xtls
          }
        ]
      },
      "streamSettings": {
        "grpcSettings": {
          "multiMode": true,
          "serviceName": "ss-grpc"
        },
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "allowInsecure": true,
          "serverName": "$sni"
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }
  ],
  "policy": {
    "levels": {
      "8": {
        "connIdle": 300,
        "downlinkOnly": 1,
        "handshake": 4,
        "uplinkOnly": 1
      }
    },
    "system": {
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "Asls",
"rules": []
  },
  "stats": {}
}
EOF

# // Link
export link="http://${IP_NYA}:85/${user}-tls";
export link0="http://${IP_NYA}:85/${user}-none";
export link1="http://${IP_NYA}:85/${user}-grpc";

# // SS WS TLS
sed -i '/#ssws$/a\### '"$user $exp"'\
},{"password": "'""$PWD_NYA""'","email": "'""$user""'"' /usr/local/etc/xray/ss.json

# // SS GRPC TLS
sed -i '/#ssgrpc$/a\### '"$user $exp"'\
},{"password": "'""$PWD_NYA""'","email": "'""$user""'"' /usr/local/etc/xray/ss.json

echo -e "SS $user $exp" >> /usr/local/etc/xray/user.txt

systemctl restart xray@ss.service

sleep 1
clear;
echo -e "";
echo -e "======-XRAY-SS/WS&GRPC-=======";
echo -e "REMARKS   = ${user}";
echo -e "MYIP      = ${IP_NYA}";
echo -e "SUBDOMAIN = ${dom}";
echo -e "PORT TLS  = $xtls";
echo -e "PORT NONE = $none";
echo -e "USER ID   = ${PWDR_NYA}:${PWD_NYA}";
echo -e "METHOD    = 2022-blake3-aes-128-gcm";
echo -e "==============================";
echo -e "IMPORT LINK KE CUSTOM GatchaNG "; 
echo -e "==============================";
echo -e "SHADOWSOCK WS TLS LINK";
echo -e " ${link}";
echo -e "";
echo -e "==============================";
echo -e "SHADOWSOCK WS LINK";
echo -e " ${link0}";
echo -e "";
echo -e "==============================";
echo -e "SHADOWSOCK GRPC TLS LINK";
echo -e " ${link1}";
echo -e "";
echo -e "==============================";
echo -e "EXPIRED   = $exp1";
echo -e "";
echo -e -n "PRESS [ ${BLUE}ENTER${LIGHT} ] TO MENU ${NC}"; read  menu
menu
}

clear;
echo -e "";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${NC}${BG}              ⇱ SHDWSCK22 WS & GRPC ⇲           ${BLUE}│${NC}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}┌────────────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${LIGHT}  [${GREEN}01${LIGHT}] ${RED}•${LIGHT} CREATE USER SHDWSCK22 ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}02${LIGHT}] ${RED}•${LIGHT} DELETE USER SHDWSCK22 ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}03${LIGHT}] ${RED}•${LIGHT} RENEW  USER SHDWSCK22 ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}04${LIGHT}] ${RED}•${LIGHT} CHECK  USER SHDWSCK22 ACCOUNT";
echo -e "${BLUE}│${LIGHT}  [${GREEN}05${LIGHT}] ${RED}•${LIGHT} TRIAL  USER SHDWSCK22 ACCOUNT";
echo -e "${BLUE}│${NC}"
echo -e "${BLUE}│${LIGHT}  [${RED}00${LIGHT}] ${RED}• BACK TO MENU${LIGHT}";
echo -e "${BLUE}└────────────────────────────────────────────────┘${NC}";
echo -e "${BLUE}──────────────────────────────────────────────────${NC}${LIGHT}";
echo -e"";
echo -e -n " Select menu [${GREEN} 0 - 5 ${LIGHT}] = "; read x
if [[ $x = 1 || $x = 01 ]]; then
 clear
 add-ss
 elif [[ $x = 2 || $x = 02 ]]; then
 clear
 del-ss
 elif [[ $x = 3 || $x = 03 ]]; then
 clear
 renew-ss
 elif [[ $x = 4 || $x = 04 ]]; then
 clear
 cek-ss
 elif [[ $x = 5 || $x = 05 ]]; then
 clear
 trial-ss
 elif [[ $x = 0 || $x = 00 ]]; then
 clear
 menu
 else
   echo -e " PLEASE ENTER THE CORRECT NUMBER"
 sleep 1
  menu-ss
 fi
