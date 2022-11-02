#!/bin/bash

#######################################
# Script to first minimum local-system auto/manual configure
# (users;network;ssh;iptables;etc...) for installing Mail-in-a-box on Ubuntu 22.04
# Made by Maksim Kulikov, 2022
#######################################

## COLORS ##
# Reset
Color_Off='\033[0m'       # Text Reset

# Regular Colors
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Cyan='\033[0;36m'         # Cyan

## Directives ##

TEMP_FILE=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^TEMP_FILE/{v=t($2)};END{printf "%s\n",v}' env)
# Look for your system filename here /etc/netplan/
NETPLAN_SYSTEM_FILE=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^NETPLAN_SYSTEM_FILE/{v=t($2)};END{printf "%s\n",v}' env)
# Your config
NETPLAN_MY_FILE=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^NETPLAN_MY_FILE/{v=t($2)};END{printf "%s\n",v}' env)
# Script path
IPTABLES_PATH=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^IPTABLES_PATH/{v=t($2)};END{printf "%s\n",v}' env)
MASK=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^MASK/{v=t($2)};END{printf "%s\n",v}' env)
IFACE=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^IFACE/{v=t($2)};END{printf "%s\n",v}' env)
SSH_PORT=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^SSH_PORT/{v=t($2)};END{printf "%s\n",v}' env)
RSA_NAME=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^RSA_NAME/{v=t($2)};END{printf "%s\n",v}' env)
USERNAME_SSH=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^USERNAME_SSH/{v=t($2)};END{printf "%s\n",v}' env)
# Web
PORTS_1=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^PORTS_1/{v=t($2)};END{printf "%s\n",v}' env)
# Mail & ssh
PORTS_2=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^PORTS_2/{v=t($2)};END{printf "%s\n",v}' env)
# DNS
PORTS_3=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^PORTS_3/{v=t($2)};END{printf "%s\n",v}' env)

# For network
NETWORK=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^NETWORK/{v=t($2)};END{printf "%s\n",v}' env)
MAIN_IP=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^MAIN_IP/{v=t($2)};END{printf "%s\n",v}' env)
GATEWAY=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^GATEWAY/{v=t($2)};END{printf "%s\n",v}' env)
DNS_NAMESERVERS=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^DNS_NAMESERVERS/{v=t($2)};END{printf "%s\n",v}' env)
NETMASK=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^NETMASK/{v=t($2)};END{printf "%s\n",v}' env)
HOSTNAME=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^HOSTNAME/{v=t($2)};END{printf "%s\n",v}' env)
WHITE_IP=$(awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^WHITE_IP/{v=t($2)};END{printf "%s\n",v}' env)

## Functions ##
# Run a command in the background.
_evalBgr() {
    eval "$@" &>/dev/null & disown;
}

# Dirs
sudo touch /etc/network/interfaces
sudo touch $TEMP_FILE
sudo touch /etc/iptables_rules
# For logs
  exec 2>logs+errors
# Create new user and add sudo priviliges
echo -e "$Cyan \n Create new user? $Color_Off"
  echo "1 - yes, 2 - no"
  read user_create
  case $user_create in
    1)
    sleep 2
    echo -e "$Yellow \n Enter new user name!: $Color_Off"
    read -p "Username: " user
    sudo useradd -m $user
    echo -e "$Yellow \n Enter new user password!: $Color_Off"
    read -s -p "User password: " u_pswd
    sudo passwd $u_pswd ;;
    2)
    echo -e "$Red \n aborted $Color_Off"
    sleep 1 ;;
    *)
    echo -e "$Red \n error $Color_Off"
    sleep 1
    esac

echo -e "$Cyan \n Install root priviliges for selected user? $Color_Off"
  echo "1 - yes, 2 - no"
  read user_root
  case $user_root in
   1)
   sleep 2
   echo -e "$Yellow \n Enter your username for root!!!: $Color_Off"
   read -p "Username Root: " user
   sudo usermod -aG sudo $user ;;
   2)
   echo -e "$Red \n aborted $Color_Off"
   sleep 1 ;;
   *)
   echo -e "$Red \n error $Color_Off"
   sleep 1
   esac

# Install tools
echo -e "$Cyan \n Begin install soft/tools and undate system... $Color_Off"

sudo apt install net-tools mc curl
sudo apt-get install htop iptables-persistent sshpass
# Install atom
wget -qO - https://packagecloud.io/AtomEditor/atom/gpgkey | sudo apt-key add -
sudo sh -c 'echo "deb [arch=amd64] https://packagecloud.io/AtomEditor/atom/any/ any main" > /etc/apt/sources.list.d/atom.list'
sudo apt-get update
sudo apt-get install atom
sudo apt-get install atom-beta
# Update/upgrade
sudo apt update
sudo apt upgrade
sudo apt full-upgrade
sudo apt autoremove

echo -e "$Yellow \n done $Color_Off"
sleep 2

# Install network via NETPLAN
echo -e "$Cyan \n Your current network $Color_Off"
sudo lshw -C network
echo -e "$Cyan \n Begin install network setings with NETPLAN? $Color_Off"
  echo "begin install network"
    echo '1 -import from file, 2 -manual, 3-skip'
    read netplan
    case $netplan in
       1)
       sudo chmod 0777 /etc/netplan/$NETPLAN_SYSTEM_FILE
       cat $NETPLAN_MY_FILE > /etc/netplan/$NETPLAN_SYSTEM_FILE
       sudo systemctl start systemd-networkd
       sudo netplan generate
       sudo netplan apply
       echo "done"
       sleep 1 ;;
       2)
       sudo chmod 0777 /etc/netplan/$NETPLAN_SYSTEM_FILE
       sudo mcedit /etc/netplan/$NETPLAN_SYSTEM_FILE
       sudo systemctl start systemd-networkd
       sudo netplan generate
       sudo netplan apply
       echo "done"
       sleep 1 ;;
       3)
       echo -e "$Green \n OK.SKIP $Color_Off"
       sleep 1 ;;
       *)
       echo -e "$Red \n error $Color_Off"
       sleep 1
       esac

# Fix some problemls with connections
echo -e "$Cyan \n Check your network. Do you have some problems? fix it?... $Color_Off"
  echo "fix problem?"
    echo '1 -no,everything is ok, 2 -yes'
    read fix_int
    case $fix_int in
       1)
       echo -e "$Green \n OK.SKIP $Color_Off"
       sleep 1 ;;
       2)
       sudo ifconfig $IFACE up
       sudo ip addr add $MAIN_IP/$MASK dev $IFACE
       ip r sh
       sudo route add default gw $GATEWAY
       sudo chmod 0777 /etc/resolv.conf

       if [ -d "$TEMP_FILE" ]; then
         echo "$TEMP_FILE already exist!"
       elif [ ! -d "$TEMP_FILE" ]; then
         sudo touch $TEMP_FILE
       fi

       sudo chmod 0777 $TEMP_FILE
       echo "" > $TEMP_FILE
       echo "nameserver $DNS_NAMESERVERS" >> /etc/resolv.conf
       wait
       sudo awk '!seen[$0]++' /etc/resolv.conf > $TEMP_FILE
       wait
       cat $TEMP_FILE > /etc/resolv.conf
       sleep 1 ;;
       *)
       echo -e "$Red \n error $Color_Off"
       sleep 1
       esac

# Restart network manager
echo -e "$Cyan \n restart network manager... $Color_Off"
sudo systemctl restart NetworkManager
sleep 1
echo -e "$Green \n Done $Color_Off"

# Install ssh
echo -e "$Cyan \n Begin install SSH... $Color_Off"

sleep 2
sudo apt install openssh-server
sudo /lib/systemd/systemd-sysv-install enable ssh

echo -e "$Yellow \n select install method auto or manual $Color_Off"
  echo '1 -auto install, 2 -manual'
  read ssh_install
  case $ssh_install in
  1)
  echo 'begin install...'
  sleep 2
  cd /etc/ssh/
  sudo sed -i "s/#Port 22/Port $SSH_PORT/" sshd_config
  sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' sshd_config
  sleep 2
  echo "done" ;;
  2)
  sudo mcedit /etc/ssh/sshd_config ;;
  *)
  echo -e "$Red \n error $Color_Off"
  sleep 1
  esac

# SSH generation
echo -e "$Green \n Begin generation... $Color_Off"
sleep 2

ssh-keygen -f /home/$USERNAME_SSH/.ssh/rsa-$RSA_NAME
sudo apt-get update
sudo systemctl restart sshd
echo -e "$Green \n Done $Color_Off"
echo -e "$Green \n copy key on server... $Color_Off"
sleep 1
ssh-copy-id -p $SSH_PORT -i /home/$USERNAME_SSH/.ssh/rsa-$RSA_NAME.pub $USERNAME_SSH@$MAIN_IP
echo -e "$Green \n Done $Color_Off"

# Login setup
echo -e "$Cyan \n Pre-configure SSH... $Color_Off"

echo "select method auto or manual"
  echo '1 -auto configure, 2 -manual, 3 -skip'
  read conf_ssh
  case $conf_ssh in
  1)
  echo 'begin configure...'
  sleep 2
  sudo sed -i 's/#PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
  sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
  sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sudo sed -i 's/#PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sleep 2
  echo "done" ;;
  2)
  sudo mcedit /etc/ssh/sshd_config ;;
  3)
  echo -e "$Red \n aborted $Color_Off"
  sleep 1 ;;
  *)
  echo -e "$Red \n error $Color_Off"
  sleep 1
  esac

echo -e "$Cyan \n Begin restart ssh... $Color_Off"
sleep 1
sudo systemctl restart ssh
echo -e "$Green \n Done $Color_Off"
sleep 2

# Login background check/out
echo -e "$Cyan \n Try login via ssh... $Color_Off"
sudo chmod 0777 $TEMP_FILE
echo "" > $TEMP_FILE
sleep 1

echo -e "$Yellow \n Enter ssh password for $USERNAME_SSH@$MAIN_IP server!: $Color_Off"
read -s -p "SSH PASSWORD: " SSH_PSWD
#cmd="ssh -p $SSH_PORT -i /home/$USERNAME_SSH/.ssh/rsa-vm-wp $USERNAME_SSH@$MAIN_IP > $TEMP_FILE &";
cmd="sshpass -p "$SSH_PSWD" ssh -p $SSH_PORT $USERNAME_SSH@$MAIN_IP > $TEMP_FILE &";
_evalBgr "${cmd}";
sleep 2
export_data=$(<$TEMP_FILE)
grep -q "Welcome to" $TEMP_FILE; [ $? -eq 0 ] && echo ">>> SUCCESS CONNECTION <<<" || echo "??? ERROR CONNECTION ???"
sleep 2

# Configure SSH
echo -e "$Cyan \n Edit configuration ssh auto or manual... $Color_Off"
echo '' > /home/$USERNAME_SSH/.ssh/config
  echo '1 -auto , 2 -manual, 3 -exit'
  read ssh_conf
  case $ssh_conf in
  1)
  echo 'begin configure...'
  sleep 2
  echo "Host $RSA_NAME" >>  /home/$USERNAME_SSH/.ssh/config
  echo "User $USERNAME_SSH" >> /home/$USERNAME_SSH/.ssh/config
  echo "HostName $MAIN_IP" >> /home/$USERNAME_SSH/.ssh/config
  echo "Port $SSH_PORT" >> /home/$USERNAME_SSH/.ssh/config
  echo "IdentityFile /home/$USERNAME_SSH/.ssh/rsa-$RSA_NAME" >> /home/$USERNAME_SSH/.ssh/config
  echo "done"
  sleep 2 ;;
  2)
  sudo mcedit /home/$USERNAME_SSH/.ssh/config ;;
  3)
  echo -e "$Red \n aborted $Color_Off"
  sleep 1 ;;
  *)
  echo -e "$Red \n error $Color_Off"
  sleep 1
  esac

#Configure iptables_firewall
echo -e "$Cyan \n Begin configure IPTABLES FIREWALL... $Color_Off"
echo "select configure method auto or manual"
   echo '1 -auto , 2 -manual'
   read iptables_conf
   case $iptables_conf in
    1)
    echo 'begin configure...'
    sleep 2

    if [ -d "$IPTABLES_PATH" ]; then
      echo "$IPTABLES_PATH already exist!"
    elif [ ! -d "$IPTABLES_PATH" ]; then
      sudo touch $IPTABLES_PATH
    fi

    wait
    sudo chmod 0777 $IPTABLES_PATH
    sudo chmod 0777 /sbin/iptables-save
    sudo chmod 0777 /etc/iptables_rules
    echo "" > $IPTABLES_PATH
    wait
    echo "#!/bin/bash" >> $IPTABLES_PATH
    # web
    echo "iptables -I INPUT -p tcp --match multiport --dports $PORTS_1 -j ACCEPT" >> $IPTABLES_PATH
    # mail
    echo "iptables -I INPUT -p tcp --match multiport --dports $PORTS_2 -j ACCEPT" >> $IPTABLES_PATH
    echo "iptables -A INPUT -p udp -m udp --dport $PORTS_3 -j ACCEPT" >> $IPTABLES_PATH
    echo "iptables -A OUTPUT -p udp -m udp --sport $PORTS_3 -j ACCEPT" >> $IPTABLES_PATH
    # path rules
    echo "/sbin/iptables-save > /etc/iptables_rules" >> $IPTABLES_PATH
    echo -e "$Green \n Done $Color_Off"
    sleep 2 ;;
    2)
    sudo mcedit $IPTABLES_PATH ;;
    *)
    echo -e "$Red \n error $Color_Off"
    sleep 1
    esac

# Check rules
echo -e "$Cyan \n Check/Run rules... $Color_Off"
if [ -d "/run/xtables.lock" ]; then
  echo "/run/xtables.lock already exist!"
elif [ ! -d "/run/xtables.lock" ]; then
  sudo touch /run/xtables.lock
fi
sudo /bin/bash $IPTABLES_PATH
sudo iptables -L -v -n
sleep 1
echo -e "$Green \n Done $Color_Off"
sleep 1

# Save rules
echo -e "$Cyan \n Save IPTABLES rules... $Color_Off"
sudo netfilter-persistent save
sudo /sbin/iptables-save > /etc/iptables_rules
sleep 2
echo -e "$Green \n Done $Color_Off"
sleep 1

# Edit host file
echo -e "$Cyan \n Editing host file $Color_Off"
if [ -d "$TEMP_FILE" ]; then
  echo "$TEMP_FILE already exist!"
elif [ ! -d "$TEMP_FILE" ]; then
  sudo touch $TEMP_FILE
fi
sudo chmod 0777 $TEMP_FILE
sudo chmod 0777 /etc/hosts
echo "" > $TEMP_FILE
awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^MAIN_IP/{m=t($2)};/^HOSTNAME/{h=t($2)};END{printf "%s   %s\n",m,h}' env >> /etc/hosts
awk -F '=' 'function t(s){gsub(/[[:space:]]/,"",s);return s};/^WHITE_IP/{m=t($2)};/^HOSTNAME/{h=t($2)};END{printf "%s   %s\n",m,h}' env >> /etc/hosts
wait
sudo awk '!seen[$0]++' /etc/hosts > $TEMP_FILE
wait
cat $TEMP_FILE > /etc/hosts
sudo chmod 0755 /etc/hosts
sleep 1
echo -e "$Green \n Done $Color_Off"

# Additional configure for iptables
echo -e "$Cyan \n Additional configure for iptables $Color_Off"
sudo depmod -a
sudo modprobe ip_tables
sudo iptables -nL
sleep 1
echo -e "$Green \n Done $Color_Off"

# Fix priviliges
echo -e "$Cyan \n Fix priviliges $Color_Off"
sudo chmod 0755 /sbin/iptables-save
sudo chmod 0755 /etc/iptables_rules
sudo chmod 0755 /etc/resolv.conf
sudo chmod 0755 /etc/netplan/$NETPLAN_SYSTEM_FILE
sleep 1
echo -e "$Green \n Done $Color_Off"

# Install Mail-in-a-box
echo -e "$Cyan \n Begin install Mail-in-a-Box $Color_Off"
sleep 1
sudo curl -s https://mailinabox.email/setup.sh | sudo bash
echo -e "$Green \n Done $Color_Off"
