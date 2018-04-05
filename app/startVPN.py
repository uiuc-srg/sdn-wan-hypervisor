import os as os
import requests

def init_switch_ip(ip_addr, subnetMask):
    command = "ifconfig ovsbr0 " + ip_addr + "/" + str(subnetMask) +" up"
    print (command)
    os.system(command)
    os.system("route -n")

def startServiceVPNServer(nodeAddr, keyDirStr, keyNameStr, subNetStr, serverAddrStr, privatenetsStr, vpnClientsStr):
    # os.system("route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.2.10")
    # os.system("route add -net 10.0.200.0 netmask 255.255.255.0 gw 10.0.2.10")
    res = requests.post("http://" + nodeAddr + '/startVPNserver',
                        json={"keyDir": keyDirStr,
                              "keyName": keyNameStr,
                              "subnet": subNetStr,
                              "vpnserver": serverAddrStr,
                              "privatenets": privatenetsStr,
                              "vpnclients": vpnClientsStr
                              })
    if res.ok:
        print("server start request sent")
        return True
    else:
        return False


def startServiceVPNClient(nodeAddr, keyDirStr, keyNameStr, serverAddrStr, nextHopStr):
    res = requests.post("http://" + nodeAddr + '/startVPNClient',
                        json={"keyDir": keyDirStr,
                              "keyName": keyNameStr,
                              "vpnserver": serverAddrStr,
                              "nextHop": nextHopStr,
                              })
    if res.ok:
        print("client start request sent")
        return True
    else:
        return False
