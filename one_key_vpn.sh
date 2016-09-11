#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

mkdir tmp
cd tmp

[ ! -e '/usr/bin/curl' ] && yum -y install curl
VPN_IP=$(curl -s -4 ipinfo.io | grep "ip" | awk -F\" '{print $4}')

PPTP_LOCAL="192.168.0.150"
PPTP_REMOTE="192.168.0.151-200"

CERT_C="cn"
CERT_O="wofanvpn"
CERT_CN="VPN WOFAN"

OS="1"
CUR_DIR=`pwd`

PSK='iwofan'
USER_NAME='iwofan'
USER_PASS='123123'

ROOT_PASSWD='###'
SECRETS_PATH=/root/secrets

function rootness(){

if [[ $EUID -ne 0 ]]; then
   echo "Error:This script must be run as root!" 1>&2
   exit 1
fi
#change root password
#echo root:${ROOT_PASSWD} | chpasswd

}

# Disable selinux
function disable_selinux(){

if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
fi

}

function getVirt(){

	yum install -y virt-what
    if [ `virt-what` = "openvz" ]; then
        OS="2"
    fi
    yum remove -y virt-what

}


function pre_install(){

	cd $CUR_DIR

	if ! wget --no-check-certificate -O ez_setup.py https://bootstrap.pypa.io/ez_setup.py; then
        echo "Failed to download ez_setup.py!"
        exit 1
    fi
    if ! wget --no-check-certificate https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks -O /etc/init.d/shadowsocks; then
        echo "Failed to download shadowsocks chkconfig file!"
        exit 1
    fi
    if ! wget --no-check-certificate https://download.strongswan.org/strongswan-5.3.5.tar.gz;then
        echo "Failed to download strongswan.tar.gz"
        exit 1
    fi
}

function yum_install_and_ppp(){
    
    yum -y update
    
    rpm -Uvh http://poptop.sourceforge.net/yum/stable/rhel6/pptp-release-current.noarch.rpm
    
    yum -y install pam-devel openssl-devel make gcc gcc-c++ \
    iptables ppp pptpd unzip swig python python-devel python-setuptools \
    autoconf libtool libevent automake curl-devel zlib-devel perl perl-devel \
    cpio expat-devel gettext-devel xl2tpd

}

function install_strongswan(){

	cd $CUR_DIR

	tar xzf strongswan*.tar.gz
    cd $CUR_DIR/strongswan-*/

    if [ "$OS" = "1" ]; then
        ./configure  --enable-eap-identity --enable-eap-md5 \
--enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
--enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
--enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
--enable-certexpire --enable-radattr --enable-tools --enable-openssl --disable-gmp

    else
        ./configure  --enable-eap-identity --enable-eap-md5 \
--enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
--enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
--enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
--enable-certexpire --enable-radattr --enable-tools --enable-openssl --disable-gmp --enable-kernel-libipsec

    fi
    make; make install
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
            chkconfig --add shadowsocks
            chkconfig shadowsocks on
        else
            echo "Shadowsocks install failed!"
            exit 1
        fi
        clear
    else
        echo "pip install failed!"
        exit 1
    fi

}

function export_key(){

    cd $CUR_DIR

    mkdir ipsec_key
    cd ipsec_key

    ipsec pki --gen --outform pem > ca.pem
    ipsec pki --self --in ca.pem --dn "C=${CERT_C}, O=${CERT_O}, CN=${CERT_CN}" --ca --outform pem >ca.cert.pem
    ipsec pki --gen --outform pem > server.pem  
    ipsec pki --pub --in server.pem | ipsec pki --issue --cacert ca.cert.pem \
--cakey ca.pem --dn "C=${CERT_C}, O=${CERT_O}, CN=${VPN_IP}" \
--san="${VPN_IP}" --flag serverAuth --flag ikeIntermediate \
--outform pem > server.cert.pem
    ipsec pki --gen --outform pem > client.pem  
    ipsec pki --pub --in client.pem | ipsec pki --issue --cacert ca.cert.pem --cakey ca.pem --dn "C=${CERT_C}, O=${CERT_O}, CN=${CERT_CN}" --outform pem > client.cert.pem
    openssl pkcs12 -export -inkey client.pem -in client.cert.pem -name "client" -certfile ca.cert.pem -caname "${CERT_CN}"  -out client.cert.p12 -passout pass:${USER_PASS}

    cp -r ca.cert.pem /usr/local/etc/ipsec.d/cacerts/
    cp -r server.cert.pem /usr/local/etc/ipsec.d/certs/
    cp -r server.pem /usr/local/etc/ipsec.d/private/
    cp -r client.cert.pem /usr/local/etc/ipsec.d/certs/
    cp -r client.pem  /usr/local/etc/ipsec.d/private/
    
}

function config_pptp(){

	[ -z "`grep '^localip' /etc/pptpd.conf`" ] && echo "localip $PPTP_LOCAL" >> /etc/pptpd.conf  
	[ -z "`grep '^remoteip' /etc/pptpd.conf`" ] && echo "remoteip $PPTP_REMOTE" >> /etc/pptpd.conf

	if [ -z "`grep '^ms-dns' /etc/ppp/options.pptpd`" ];then
		echo "ms-dns 8.8.8.8" >> /etc/ppp/options.pptpd # Google DNS Primary
		echo "ms-dns 209.244.0.3" >> /etc/ppp/options.pptpd # Level3 Primary
		echo "ms-dns 208.67.222.222" >> /etc/ppp/options.pptpd # OpenDNS Primary
	fi

	chkconfig pptpd on
	clear

}

function config_xl2tp(){
    cat > /etc/ppp/options.xl2tpd<<-EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns  8.8.8.8
ms-dns  8.8.4.4
# noccp
auth
crtscts
idle 1800
mtu 1410
mru 1410
nodefaultroute
debug
lock
proxyarp
connect-delay 5000

name xl2tpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
persist
logfile /var/log/xl2tpd.log
EOF

    echo "ms-dns 209.244.0.3" >> /etc/ppp/options.xl2tpd # Level3 Primary
    echo "ms-dns 208.67.222.222" >> /etc/ppp/options.xl2tpd # OpenDNS Primary
    chkconfig xl2tpd on
}


# configure the strongswan.conf
function config_strongswan(){
	cat > /usr/local/etc/strongswan.conf<<-EOF
charon {
        load_modular = yes
        duplicheck.enable = no
        compress = yes
        plugins {
                include strongswan.d/charon/*.conf
        }
        dns1 = 8.8.8.8
        dns2 = 8.8.4.4
        nbns1 = 8.8.8.8
        nbns2 = 8.8.4.4
}
include strongswan.d/*.conf
EOF
}

# configure the ipsec.conf
function config_ipsec(){
	cat > /usr/local/etc/ipsec.conf<<-EOF
config setup
    uniqueids=never 
conn l2tp
    keyexchange=ikev1
    left=${VPN_IP}
    leftsubnet=0.0.0.0/0
    leftprotoport=17/1701
    authby=secret
    leftfirewall=no
    right=%any
    rightprotoport=17/%any
    type=transport
    auto=add
conn iOS_cert
    keyexchange=ikev1
    fragmentation=yes
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightauth2=xauth
    rightsourceip=10.31.2.0/24
    rightcert=client.cert.pem
    auto=add
conn android_xauth_psk
    keyexchange=ikev1
    left=%defaultroute
    leftauth=psk
    leftsubnet=0.0.0.0/0
    right=%any
    rightauth=psk
    rightauth2=xauth
    rightsourceip=10.31.2.0/24
    auto=add
conn networkmanager-strongswan
    keyexchange=ikev2
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightsourceip=10.31.2.0/24
    rightcert=client.cert.pem
    auto=add
conn ios_ikev2
    keyexchange=ikev2
    ike=aes256-sha256-modp2048,3des-sha1-modp2048,aes256-sha1-modp2048!
    esp=aes256-sha256,3des-sha1,aes256-sha1!
    rekey=no
    left=%defaultroute
    leftid=${VPN_IP}
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=10.31.2.0/24
    rightsendcert=never
    eap_identity=%any
    dpdaction=clear
    fragmentation=yes
    auto=add
conn windows7
    keyexchange=ikev2
    ike=aes256-sha1-modp1024!
    rekey=no
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=10.31.2.0/24
    rightsendcert=never
    eap_identity=%any
    auto=add
EOF
}

function config_iptables(){

	sysctl -w net.ipv4.ip_forward=1
	sed -i 's@net.ipv4.ip_forward.*@net.ipv4.ip_forward = 1@g' /etc/sysctl.conf
	sysctl -p /etc/sysctl.conf

	ETH=`route | grep default | awk '{print $NF}'`

	# iptables -t nat -A POSTROUTING -o $ETH -j MASQUERADE
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8989 -j ACCEPT
	iptables -I FORWARD -p tcp --syn -i ppp+ -j TCPMSS --set-mss 1356
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

    iptables -A FORWARD -s 10.31.0.0/24 -j ACCEPT
    iptables -A FORWARD -s 10.31.1.0/24 -j ACCEPT
    iptables -A FORWARD -s 10.31.2.0/24 -j ACCEPT
    iptables -A INPUT -i $ETH -p esp -j ACCEPT
    iptables -A INPUT -i $ETH -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -i $ETH -p tcp --dport 500 -j ACCEPT
    iptables -A INPUT -i $ETH -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -i $ETH -p udp --dport 1701 -j ACCEPT
    iptables -A INPUT -i $ETH -p tcp --dport 1723 -j ACCEPT
    #use snat
    iptables -t nat -A POSTROUTING -o $ETH -j SNAT --to-source $VPN_IP
    iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $ETH -j SNAT --to-source $VPN_IP
    iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $ETH -j SNAT --to-source $VPN_IP
    iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $ETH -j SNAT --to-source $VPN_IP

    service iptables save

    sed -i '/^-A INPUT -j REJECT --reject-with icmp-host-prohibited/d' /etc/sysconfig/iptables 
	sed -i '/^-A FORWARD -j REJECT --reject-with icmp-host-prohibited/d' /etc/sysconfig/iptables 
	
	service iptables restart
	chkconfig iptables on
}

# configure the ipsec.secrets
function config_secrets(){

#pptp and xl2tp
	echo "${USER_NAME} * ${USER_PASS} *" >> /etc/ppp/chap-secrets
	service pptpd restart
    service xl2tpd restart

#shadowsocks
    cat > /etc/shadowsocks.json<<-EOF
{
    "server":"${VPN_IP}",
    "local_address":"127.0.0.1",
    "local_port":1080,
    "port_password":{
    "8989":"${USER_PASS}"
    },
    "timeout":300,
    "method":"aes-256-cfb",
    "fast_open":false
}
EOF
	/etc/init.d/shadowsocks restart
#ipsec
    cat > /usr/local/etc/ipsec.secrets<<-EOF
: RSA server.pem
: PSK "${PSK}"
: XAUTH "${PSK}"
include /usr/local/etc/chap-secrets
EOF
    cat > /usr/local/etc/chap-secrets<<-EOF
${USER_NAME} %any : EAP "${USER_PASS}"
EOF
	ipsec restart

}

function change_port(){
	#change ssh port
	sed -i '$s/^.*$/port 22/' /etc/ssh/sshd_config
	service sshd restart
}

function cleanup(){

    mkdir -p ${SECRETS_PATH}
    mv $CUR_DIR/ipsec_key/ ${SECRETS_PATH}/

    ln -s /usr/local/etc/ipsec.secrets ${SECRETS_PATH}/key.secrets 
    ln -s /etc/shadowsocks.json ${SECRETS_PATH}/shadowsocks.secrets 
    ln -s /usr/local/etc/chap-secrets ${SECRETS_PATH}/ipsec.secrets 
    ln -s /etc/ppp/chap-secrets ${SECRETS_PATH}/ppp.secrets

    rm -rf $CUR_DIR
}

rootness
disable_selinux
pre_install
getVirt
yum_install_and_ppp
install_strongswan
install_shadowsocks
export_key
config_pptp
config_xl2tp
config_ipsec
config_strongswan
config_iptables
config_secrets
#change_port
cleanup

