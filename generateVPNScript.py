from jinja2 import Template


def generateVPNServerScript(keyDirStr, keyNameStr, subNetStr, serverAddrStr, privatenetsStr, vpnClientsStr):
    template = Template('''
#!/bin/sh
# custom VPN Server Configuration for service (security.py)
# -------- CUSTOMIZATION REQUIRED --------
#
# The VPNServer service sets up the OpenVPN server for building VPN tunnels
# that allow access via TUN/TAP device to private networks.
#
# note that the IPForward and DefaultRoute services should be enabled

# directory containing the certificate and key described below, in addition to
# a CA certificate and DH key


keydir={{ keyDir }}

# the name used for a "$keyname.crt" certificate and "$keyname.key" private key.
keyname={{ keyName }}

# the VPN subnet address from which the client VPN IP (for the TUN/TAP)
# will be allocated
vpnsubnet={{ subNet }}

# public IP address of this vpn server (same as VPNClient vpnserver= setting)
vpnserver={{ serverAddr }}

# optional list of private subnets reachable behind this VPN server
# each subnet and next hop is separated by a space
# "<subnet1>,<nexthop1> <subnet2>,<nexthop2> ..."
privatenets="{{ privatenets }}"

# optional list of VPN clients, for statically assigning IP addresses to
# clients; also, an optional client subnet can be specified for adding static
# routes via the client
# Note: VPN addresses x.x.x.0-3 are reserved
# "<keyname>,<vpnIP>,<subnetIP> <keyname>,<vpnIP>,<subnetIP> ..."
# vpnclients="client1,10.0.200.5,10.0.0.0"
vpnclients="{{ vpnClients }}"

# NOTE: you may need to enable the StaticRoutes service on nodes within the
# private subnet, in order to have routes back to the client.
# /sbin/ip ro add <vpnsubnet>/24 via <vpnServerRemoteInterface>
# /sbin/ip ro add <vpnClientSubnet>/24 via <vpnServerRemoteInterface>

# -------- END CUSTOMIZATION --------

echo > $PWD/vpnserver.log
#rm -f -r $PWD/ccd

# validate key and certification files
if [ ! -e $keydir\/$keyname.key ] || [ ! -e $keydir\/$keyname.crt ] \
   || [ ! -e $keydir\/ca.crt ] || [ ! -e $keydir\/dh2048.pem ]; then
     echo "ERROR: missing certification or key files under $keydir \
$keyname.key or $keyname.crt or ca.crt or dh1024.pem" >> $PWD/vpnserver.log
fi

# validate configuration IP addresses
checkip=0
if [ "$(dpkg -l | grep " sipcalc ")" = "" ]; then
   echo "WARNING: ip validation disabled because package sipcalc not installed\
        " >> $PWD/vpnserver.log
   checkip=1
else
    if [ "$(sipcalc "$vpnsubnet" "$vpnserver" | grep ERR)" != "" ]; then
     echo "ERROR: invalid vpn subnet or server address \
$vpnsubnet or $vpnserver " >> $PWD/vpnserver.log
    fi
fi

# create client vpn ip pool file
(
cat << EOF
EOF
)> $PWD/ippool.txt

# create server.conf file
(
cat << EOF
# openvpn server config
local $vpnserver
server $vpnsubnet 255.255.255.0
push redirect-gateway def1
EOF
)> $PWD/server.conf

echo "before add private subnet"

# add routes to VPN server private subnets, and push these routes to clients
for privatenet in $privatenets; do
    if [ $privatenet != "" ]; then
        net=${privatenet%%,*}
        nexthop=${privatenet##*,}
        if [ $checkip = "0" ] &&
           [ "$(sipcalc "$net" "$nexthop" | grep ERR)" != "" ]; then
            echo "ERROR: invalid vpn server private net address \
$net or $nexthop " >> $PWD/vpnserver.log
    fi
        echo push route $net 255.255.255.0 >> $PWD/server.conf
        # /sbin/ip ro add $net/24 via $nexthop
        # /sbin/ip ro add $vpnsubnet/24 via $nexthop
    fi
done

echo "finsied add private subnet"

# allow subnet through this VPN, one route for each client subnet
for client in $vpnclients; do
    if [ $client != "" ]; then
        cSubnetIP=${client##*,}
        cVpnIP=${client#*,}
        cVpnIP=${cVpnIP%%,*}
        cKeyFilename=${client%%,*}
        if [ "$cSubnetIP" != "" ]; then
            if [ $checkip = "0" ] &&
               [ "$(sipcalc "$cSubnetIP" "$cVpnIP" | grep ERR)" != "" ]; then
                echo "ERROR: invalid vpn client and subnet address \
$cSubnetIP or $cVpnIP " >> $PWD/vpnserver.log
        fi
            echo route $cSubnetIP 255.255.255.0  >> $PWD/server.conf
            if ! test -d $PWD/ccd; then
                mkdir -p $PWD/ccd
                echo  client-config-dir $PWD/ccd >> $PWD/server.conf
            fi
            if test -e $PWD/ccd/$cKeyFilename; then
              echo iroute $cSubnetIP 255.255.255.0 >> $PWD/ccd/$cKeyFilename
            else
              echo iroute $cSubnetIP 255.255.255.0 > $PWD/ccd/$cKeyFilename
            fi
        fi
        if [ "$cVpnIP" != "" ]; then
            echo $cKeyFilename,$cVpnIP >> $PWD/ippool.txt
        fi
    fi
done

echo "finsied assign routes"


(
cat << EOF
keepalive 10 120
ca $keydir/ca.crt
cert $keydir/$keyname.crt
key $keydir/$keyname.key
dh $keydir/dh2048.pem
cipher AES-256-CBC
status /var/log/openvpn-status.log
log /var/log/openvpn-server.log
ifconfig-pool-linear
ifconfig-pool-persist $PWD/ippool.txt
port 1194
proto udp
dev tun
verb 4
daemon
EOF
)>> $PWD/server.conf


sysctl -w net.ipv4.ip_forward=1
# start vpn server
openvpn --config server.conf
    ''')
    config = template.render(keyDir=keyDirStr, keyName=keyNameStr, subNet=subNetStr, serverAddr=serverAddrStr, privatenets=privatenetsStr, vpnClients=vpnClientsStr)
    return config


def generateVPNClientScript(keyDirStr, keyNameStr, serverAddrStr, nextHopStr):
    template = Template('''
#!/bin/sh
# custom VPN Client configuration for service (security.py)
# -------- CUSTOMIZATION REQUIRED --------
#
# The VPNClient service builds a VPN tunnel to the specified VPN server using
# OpenVPN software and a virtual TUN/TAP device.

# directory containing the certificate and key described below
ip route del default via 10.0.0.1

keydir={{ keyDir }}

# the name used for a "$keyname.crt" certificate and "$keyname.key" private key.
keyname={{ keyName }}

# the public IP address of the VPN server this client should connect with
vpnserver="{{ serverAddr }}"

# optional next hop for adding a static route to reach the VPN server
nexthop="{{ nextHop }}"

# --------- END CUSTOMIZATION --------

# validate addresses
if [ "$(dpkg -l | grep " sipcalc ")" = "" ]; then
    echo "WARNING: ip validation disabled because package sipcalc not installed
         " > $PWD/vpnclient.log
else
    if [ "$(sipcalc "$vpnserver" "$nexthop" | grep ERR)" != "" ]; then
        echo "ERROR: invalide address $vpnserver or $nexthop \
             " > $PWD/vpnclient.log
    fi
fi

# validate key and certification files
if [ ! -e $keydir\/$keyname.key ] || [ ! -e $keydir\/$keyname.crt ] \
   || [ ! -e $keydir\/ca.crt ] || [ ! -e $keydir\/dh2048.pem ]; then
     echo "ERROR: missing certification or key files under $keydir \
$keyname.key or $keyname.crt or ca.crt or dh1024.pem" >> $PWD/vpnclient.log
fi

# if necessary, add a static route for reaching the VPN server IP via the IF
# vpnservernet=${vpnserver%.*}.0/24
# if [ "$nexthop" != "" ]; then
#     /sbin/ip route add $vpnservernet via $nexthop
# fi

# create openvpn client.conf
(
cat << EOF
client
dev tun
proto udp
remote $vpnserver 1194
nobind
ca $keydir/ca.crt
cert $keydir/$keyname.crt
key $keydir/$keyname.key
dh $keydir/dh2048.pem
cipher AES-256-CBC
log $PWD/openvpn-client.log
verb 4
daemon
EOF
) > client.conf

sysctl -w net.ipv4.ip_forward=1
openvpn --config client.conf  
    ''')
    config = template.render(keyDir=keyDirStr, keyName=keyNameStr, serverAddr=serverAddrStr, nextHop=nextHopStr)
    return config
