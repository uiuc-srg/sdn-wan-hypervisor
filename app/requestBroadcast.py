import requests


def broadcastNewVPNRequest(subnet, boradcastlist):
    vpnServerAddrs = []
    vpnServerSubnets = []
    serversInfo = []
    for addr in boradcastlist:
        res = requests.post("http://" + addr + "/vpncreate", json={"subnet": subnet})
        if res.ok:
            vpnServerInfo = res.json()
            vpnServerAddrs.append(vpnServerInfo["vpnserver"])
            vpnServerSubnets.append(vpnServerInfo["privatenets"])
            serversInfo.append({"vpnserver": vpnServerInfo["vpnserver"], "privatenets": vpnServerInfo["privatenets"]})
        else:
            return []
    return serversInfo
