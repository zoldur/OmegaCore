#!/bin/bash

TMP_FOLDER=$(mktemp -d)
CONFIG_FILE="omegacoin.conf"
OMEGA_DAEMON="/usr/local/bin/omegacoind"
OMEGA_CLI="/usr/local/bin/omegacoin-cli"
OMEGA_REPO="https://github.com/omegacoinnetwork/omegacoin/releases/download/0.12.5.1/omagecoincore-0.12.5.1-linux64.zip"
SENTINEL_REPO="https://github.com/omegacoinnetwork/sentinel.git"
DEFAULTOMEGAPORT=7777
DEFAULTOMEGAUSER="omega"
NODEIP=$(curl -s4 api.ipify.org)


RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


function get_ip() {
  declare -a NODE_IPS
  for ips in $(netstat -i | awk '!/Kernel|Iface|lo/ {print $1," "}')
  do
    NODE_IPS+=($(curl --interface $ips --connect-timeout 2 -s4 api.ipify.org))
  done

  if [ ${#NODE_IPS[@]} -gt 1 ]
    then
      echo -e "${GREEN}More than one IP. Please type 0 to use the first IP, 1 for the second and so on...${NC}"
      INDEX=0
      for ip in "${NODE_IPS[@]}"
      do
        echo ${INDEX} $ip
        let INDEX=${INDEX}+1
      done
      read -e choose_ip
      NODEIP=${NODE_IPS[$choose_ip]}
  else
    NODEIP=${NODE_IPS[0]}
  fi
}


function compile_error() {
if [ "$?" -gt "0" ];
 then
  echo -e "${RED}Failed to compile $@. Please investigate.${NC}"
  exit 1
fi
}


function checks() {
if [[ $(lsb_release -d) != *16.04* ]]; then
  echo -e "${RED}You are not running Ubuntu 16.04. Installation is cancelled.${NC}"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}$0 must be run as root.${NC}"
   exit 1
fi

if [ -n "$(pidof $OMEGA_DAEMON)" ] || [ -e "$OMEGA_DAEMOM" ] ; then
  echo -e "${GREEN}\c"
  read -e -p "Omega is already installed. Do you want to add another MN? [Y/N]" NEW_OMEGA
  echo -e "{NC}"
  clear
else
  NEW_OMEGA="new"
fi
}

function prepare_system() {

echo -e "Prepare the system to install Omega master node."
apt-get update >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get update > /dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y -qq upgrade >/dev/null 2>&1
apt install -y software-properties-common >/dev/null 2>&1
echo -e "${GREEN}Adding bitcoin PPA repository"
apt-add-repository -y ppa:bitcoin/bitcoin >/dev/null 2>&1
echo -e "Installing required packages, it may take some time to finish.${NC}"
apt-get update >/dev/null 2>&1
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" make software-properties-common \
build-essential libtool autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev libboost-program-options-dev \
libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git wget pwgen curl libdb4.8-dev bsdmainutils libdb4.8++-dev \
libminiupnpc-dev libgmp3-dev ufw python-virtualenv unzip >/dev/null 2>&1
clear
if [ "$?" -gt "0" ];
  then
    echo -e "${RED}Not all required packages were installed properly. Try to install them manually by running the following commands:${NC}\n"
    echo "apt-get update"
    echo "apt -y install software-properties-common"
    echo "apt-add-repository -y ppa:bitcoin/bitcoin"
    echo "apt-get update"
    echo "apt install -y make build-essential libtool software-properties-common autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev \
libboost-program-options-dev libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git pwgen curl libdb4.8-dev \
bsdmainutils libdb4.8++-dev libminiupnpc-dev libgmp3-dev ufw fail2ban python-virtualenv unzip"
 exit 1
fi

clear
echo -e "Checking if swap space is needed."
PHYMEM=$(free -g|awk '/^Mem:/{print $2}')
SWAP=$(free -g|awk '/^Swap:/{print $2}')
if [ "$PHYMEM" -lt "2" ] && [ -n "$SWAP" ]
  then
    echo -e "${GREEN}Server is running with less than 2G of RAM without SWAP, creating 2G swap file.${NC}"
    SWAPFILE=$(mktemp)
    dd if=/dev/zero of=$SWAPFILE bs=1024 count=2M
    chmod 600 $SWAPFILE
    mkswap $SWAPFILE
    swapon -a $SWAPFILE
else
  echo -e "${GREEN}Server running with at least 2G of RAM, no swap needed.${NC}"
fi
clear
}

function compile_node() {
  echo -e "Download binaries. This may take some time. Press a key to continue."
  cd $TMP_FOLDER >/dev/null 2>&1
  wget -q $OMEGA_REPO >/dev/null 2>&1
  unzip $(echo $OMEGA_REPO | awk -F"/" '{print $NF}') >/dev/null 2>&1
  compile_error OmegaCoin
  cp omega* /usr/local/bin
  chmod +x /usr/local/bin/omega*
  cd - 
  rm -rf $TMP_FOLDER
  clear
}

function enable_firewall() {
  echo -e "Installing and etting up firewall to allow ingress on port ${GREEN}$OMEGAPORT${NC}"
  ufw allow $OMEGAPORT/tcp comment "OMEGA MN port" >/dev/null
  ufw allow $[OMEGAPORT+1]/tcp comment "OMEGA RPC port" >/dev/null
  ufw allow ssh comment "SSH" >/dev/null 2>&1
  ufw limit ssh/tcp >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  echo "y" | ufw enable >/dev/null 2>&1
}

function configure_systemd() {
  cat << EOF > /etc/systemd/system/$OMEGAUSER.service
[Unit]
Description=OMEGA service
After=network.target

[Service]
User=$OMEGAUSER
Group=$OMEGAUSER

Type=forking
PIDFile=$OMEGAFOLDER/$OMEGAUSER.pid

ExecStart=$OMEGA_DAEMON -daemon -pid=$OMEGAFOLDER/$OMEGAUSER.pid -conf=$OMEGAFOLDER/$CONFIG_FILE -datadir=$OMEGAFOLDER
ExecStop=-$OMEGA_CLI -conf=$OMEGAFOLDER/$CONFIG_FILE -datadir=$OMEGAFOLDER stop

Restart=always
PrivateTmp=true
TimeoutStopSec=60s
TimeoutStartSec=2s
StartLimitInterval=120s
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  sleep 3
  systemctl start $OMEGAUSER.service
  systemctl enable $OMEGAUSER.service

  if [[ -z "$(ps axo user:15,cmd:100 | egrep ^$OMEGAUSER | grep $OMEGA_DAEMON)" ]]; then
    echo -e "${RED}OMEGA is not running${NC}, please investigate. You should start by running the following commands as root:"
    echo -e "${GREEN}systemctl start $OMEGAUSER.service"
    echo -e "systemctl status $OMEGAUSER.service"
    echo -e "less /var/log/syslog${NC}"
    exit 1
  fi
}

function ask_port() {
read -p "Omega Port: " -i $DEFAULTOMEGAPORT -e OMEGAPORT
: ${OMEGAPORT:=$DEFAULTOMEGAPORT}
}

function ask_user() {
  read -p "Omega user: " -i $DEFAULTOMEGAUSER -e OMEGAUSER
  : ${OMEGAUSER:=$DEFAULTOMEGAUSER}

  if [ -z "$(getent passwd $OMEGAUSER)" ]; then
    USERPASS=$(pwgen -s 12 1)
    useradd -m $OMEGAUSER
    echo "$OMEGAUSER:$USERPASS" | chpasswd

    OMEGAHOME=$(sudo -H -u $OMEGAUSER bash -c 'echo $HOME')
    DEFAULTOMEGAFOLDER="$OMEGAHOME/.omegacoincore"
    read -p "Configuration folder: " -i $DEFAULTOMEGAFOLDER -e OMEGAFOLDER
    : ${OMEGAFOLDER:=$DEFAULTOMEGAFOLDER}
    mkdir -p $OMEGAFOLDER
    chown -R $OMEGAUSER: $OMEGAFOLDER >/dev/null
  else
    clear
    echo -e "${RED}User exits. Please enter another username: ${NC}"
    ask_user
  fi
}

function check_port() {
  declare -a PORTS
  PORTS=($(netstat -tnlp | grep $NODEIP | awk '/LISTEN/ {print $4}' | awk -F":" '{print $NF}' | sort | uniq | tr '\r\n'  ' '))
  ask_port

  while [[ ${PORTS[@]} =~ $OMEGAPORT ]] || [[ ${PORTS[@]} =~ $[OMEGAPORT-1] ]]; do
    clear
    echo -e "${RED}Port in use, please choose another port:${NF}"
    ask_port
  done
}

function create_config() {
  RPCUSER=$(pwgen -s 8 1)
  RPCPASSWORD=$(pwgen -s 15 1)
  cat << EOF > $OMEGAFOLDER/$CONFIG_FILE
rpcuser=$RPCUSER
rpcpassword=$RPCPASSWORD
rpcallowip=127.0.0.1
rpcport=$[OMEGAPORT+1]
listen=1
server=1
#bind=$NODEIP
daemon=1
port=$OMEGAPORT
EOF
}

function create_key() {
  echo -e "Enter your ${RED}Masternode Private Key${NC}. Leave it blank to generate a new ${RED}Masternode Private Key${NC} for you:"
  read -e OMEGAKEY
  if [[ -z "$OMEGAKEY" ]]; then
    su $OMEGAUSER -c "$OMEGA_DAEMON -conf=$OMEGAFOLDER/$CONFIG_FILE -datadir=$OMEGAFOLDER"
    sleep 30
    if [ -z "$(ps axo user:15,cmd:100 | egrep ^$OMEGAUSER | grep $OMEGA_DAEMON)" ]; then
     echo -e "${RED}Omega server couldn't start. Check /var/log/syslog for errors.{$NC}"
     exit 1
    fi
    OMEGAKEY=$(su $OMEGAUSER -c "$OMEGA_CLI -conf=$OMEGAFOLDER/$CONFIG_FILE -datadir=$OMEGAFOLDER masternode genkey")
    if [ "$?" -gt "0" ];
      then
       echo -e "${RED}Wallet not fully loaded, need to wait a bit more time. ${NC}"
       sleep 30
       OMEGAKEY=$(su $OMEGAUSER -c "$OMEGA_CLI -conf=$OMEGAFOLDER/$CONFIG_FILE -datadir=$OMEGAFOLDER masternode genkey")
    fi
    su $OMEGAUSER -c "$OMEGA_CLI -conf=$OMEGAFOLDER/$CONFIG_FILE -datadir=$OMEGAFOLDER stop"
  fi
}

function update_config() {
  sed -i 's/daemon=1/daemon=0/' $OMEGAFOLDER/$CONFIG_FILE
  cat << EOF >> $OMEGAFOLDER/$CONFIG_FILE
maxconnections=256
externalip=$NODEIP
masternode=1
masternodeaddr=$NODEIP:$OMEGAPORT
masternodeprivkey=$OMEGAKEY
EOF
  chown -R $OMEGAUSER: $OMEGAFOLDER >/dev/null
}


function install_sentinel() {
  SENTINELPORT=$[10001+$OMEGAPORT]
  echo -e "${GREEN}Install sentinel.${NC}"
  apt-get install virtualenv >/dev/null 2>&1
  git clone $SENTINEL_REPO $OMEGAHOME/sentinel >/dev/null 2>&1
  cd $OMEGAHOME/sentinel
  virtualenv ./venv >/dev/null 2>&1  
  ./venv/bin/pip install -r requirements.txt >/dev/null 2>&1
  cd $OMEGAHOME
  sed -i "s/19998/$SENTINELPORT/g" $OMEGAHOME/sentinel/test/unit/test_dash_config.py
  echo  "* * * * * cd $OMEGAHOME/sentinel && ./venv/bin/python bin/sentinel.py >> ~/sentinel.log 2>&1" > $OMEGAHOME/omega_cron
  chown -R $OMEGAUSER: $OMEGAHOME/sentinel >/dev/null 2>&1
  chown $OMEGAUSER: $OMEGAHOME/omega_cron
  crontab -u $OMEGAUSER $OMEGAHOME/omega_cron
  rm omega_cron >/dev/null 2>&1
}

function important_information() {
 echo
 echo -e "================================================================================================================================"
 echo -e "Omega Masternode is up and running as user ${GREEN}$OMEGAUSER${NC} and it is listening on port ${GREEN}$OMEGAPORT${NC}."
 echo -e "${GREEN}$OMEGAUSER${NC} password is ${RED}$USERPASS${NC}"
 echo -e "Configuration file is: ${RED}$OMEGAFOLDER/$CONFIG_FILE${NC}"
 echo -e "Start: ${RED}systemctl start $OMEGAUSER.service${NC}"
 echo -e "Stop: ${RED}systemctl stop $OMEGAUSER.service${NC}"
 echo -e "VPS_IP:PORT ${RED}$NODEIP:$OMEGAPORT${NC}"
 echo -e "MASTERNODE PRIVATEKEY is: ${RED}$OMEGAKEY${NC}"
 echo -e "Please check Omega is running with the following command: ${GREEN}systemctl status $OMEGAUSER.service${NC}"
 echo -e "================================================================================================================================"
}

function setup_node() {
  get_ip
  ask_user
  check_port
  create_config
  create_key
  update_config
  enable_firewall
  configure_systemd
  install_sentinel
  important_information
}


##### Main #####
clear

checks
if [[ ("$NEW_OMEGA" == "y" || "$NEW_OMEGA" == "Y") ]]; then
  setup_node
  exit 0
elif [[ "$NEW_OMEGA" == "new" ]]; then
  prepare_system
  compile_node
  setup_node
else
  echo -e "${GREEN}Omega already running.${NC}"
  exit 0
fi

