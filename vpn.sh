#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Check if user is root
[ $(id -u) != "0" ] && { echo -e "\033[31mError: You must be root to run this script\033[0m"; exit 1; } 

clear
printf "
#######################################################################
#            Installs VPN system for CentOS               #
#######################################################################
"

[ ! -e '/usr/bin/curl' ] && yum -y install curl

VPN_IP=$(curl -s -4 ipinfo.io | grep "ip" | awk -F\" '{print $4}')

VPN_LOCAL="192.168.0.150"
VPN_REMOTE="192.168.0.151-200"


function pre_install(){
	
	rpm -Uvh http://poptop.sourceforge.net/yum/stable/rhel6/pptp-release-current.noarch.rpm
	yum -y install wget make openssl gcc-c++ iptables ppp pptpd unzip openssl-devel gcc swig python python-devel python-setuptools autoconf libtool libevent automake make curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel

	if ! wget --no-check-certificate -O ez_setup.py https://bootstrap.pypa.io/ez_setup.py; then
        echo "Failed to download ez_setup.py!"
        exit 1
    fi
    if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks -O /etc/init.d/shadowsocks; then
        echo "Failed to download shadowsocks chkconfig file!"
        exit 1
    fi
}

function read_input(){

	echo "Please input username for pptp:"
    read -p "(Default username: iwofan): " VPN_USER 
    if [ "$VPN_USER" = "" ]; then
        VPN_USER="iwofan"
    fi
    echo "Please input password for pptp:"
    read -p "(Default password: 123123): " VPN_PASS 
    if [ "$VPN_PASS" = "" ]; then
        VPN_PASS="123123"
    fi
	echo "Please input password for shadowsocks:"
    read -p "(Default password: howhost.me):" SHADOWSOCKS_PASS
    if [ "$SHADOWSOCKS_PASS" = "" ]; then
        SHADOWSOCKS_PASS="howhost.me"
    fi
    echo "Please input IP for shadowsocks:"
    read -p "(Default IP: ${VPN_IP}):" SHADOWSOCKS_IP
    if [ "$SHADOWSOCKS_IP" = "" ]; then
        SHADOWSOCKS_IP="${VPN_IP}"
    fi
	clear
}

function install_shadowsocks(){
    which pip > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        python ez_setup.py install
        easy_install pip
    fi
    if [ -f /usr/bin/pip ]; then
        pip install M2Crypto
        pip install greenlet
        pip install gevent
        pip install shadowsocks
        if [ -f /usr/bin/ssserver ] || [ -f /usr/local/bin/ssserver ]; then
            chmod +x /etc/init.d/shadowsocks
            # Add run on system start up
            chkconfig --add shadowsocks
            chkconfig shadowsocks on
            # Run shadowsocks in the background
            /etc/init.d/shadowsocks start
        else
            echo ""
            echo "Shadowsocks install failed!"
            exit 1
        fi
        clear
        echo ""
        echo "Congratulations, shadowsocks install completed!"
    else
        echo ""
        echo "pip install failed!"
        exit 1
    fi
}

function config_pptp(){

	echo "1" > /proc/sys/net/ipv4/ip_forward
	sed -i 's@net.ipv4.ip_forward.*@net.ipv4.ip_forward = 1@g' /etc/sysctl.conf
	echo "$VPN_USER pptpd $VPN_PASS *" >> /etc/ppp/chap-secrets

	sysctl -p /etc/sysctl.conf

	[ -z "`grep '^localip' /etc/pptpd.conf`" ] && echo "localip $VPN_LOCAL" >> /etc/pptpd.conf # Local IP address of your VPN server
	[ -z "`grep '^remoteip' /etc/pptpd.conf`" ] && echo "remoteip $VPN_REMOTE" >> /etc/pptpd.conf # Scope for your home network

	if [ -z "`grep '^ms-dns' /etc/ppp/options.pptpd`" ];then
		echo "ms-dns 8.8.8.8" >> /etc/ppp/options.pptpd # Google DNS Primary
		echo "ms-dns 209.244.0.3" >> /etc/ppp/options.pptpd # Level3 Primary
		echo "ms-dns 208.67.222.222" >> /etc/ppp/options.pptpd # OpenDNS Primary
	fi

	service pptpd restart
	chkconfig pptpd on
	clear

}

# Config shadowsocks
function config_shadowsocks(){
    cat > /etc/shadowsocks.json<<-EOF
{
    "server":"${SHADOWSOCKS_IP}",
    "local_address":"127.0.0.1",
    "local_port":1080,
    "port_password":{
    "8989":"${SHADOWSOCKS_PASS}"
    },
    "timeout":300,
    "method":"aes-256-cfb",
    "fast_open":false
}
EOF
}

function config_iptables(){

	ETH=`route | grep default | awk '{print $NF}'`
	/etc/init.d/iptables status | grep 'POSTROUTING' | grep $ETH >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		iptables -t nat -A POSTROUTING -o $ETH -j MASQUERADE
	fi
	/etc/init.d/iptables status | grep '1356' | grep 'TCPMSS' >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		iptables -I FORWARD -p tcp --syn -i ppp+ -j TCPMSS --set-mss 1356
	fi
	/etc/init.d/iptables status | grep '8989' | grep 'ACCEPT' >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8989 -j ACCEPT
	fi
	sed -i 's@^-A INPUT -j REJECT --reject-with icmp-host-prohibited@#-A INPUT -j REJECT --reject-with icmp-host-prohibited@' /etc/sysconfig/iptables 
	sed -i 's@^-A FORWARD -j REJECT --reject-with icmp-host-prohibited@#-A FORWARD -j REJECT --reject-with icmp-host-prohibited@' /etc/sysconfig/iptables 
	
	service iptables save
	service iptables restart
	chkconfig iptables on
}

function change_port(){
	sed -i '$s/^.*$/port 22/' /etc/ssh/sshd_config
	service sshd restart
}

pre_install
read_input
config_pptp
config_shadowsocks
install_shadowsocks
config_iptables
change_port
