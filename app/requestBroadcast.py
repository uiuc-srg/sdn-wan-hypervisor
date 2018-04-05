import requests

class RequestBroadcast:
    targetListenAddrList = ["10.0.2.1:5678"]

    def broadcastNewVPNRequest(self, subnet):
        vpnServerAddrs = []
        vpnServerSubnets = []
        serversInfo = []
        for addr in self.targetListenAddrList:
            res = requests.post("http://" + addr + "/vpncreate", json={"subnet": subnet})
            if res.ok:
                vpnServerInfo = res.json()
                vpnServerAddrs.append(vpnServerInfo["vpnserver"])
                vpnServerSubnets.append(vpnServerInfo["privatenets"])
                serversInfo.append({"vpnserver": vpnServerInfo["vpnserver"], "privatenets": vpnServerInfo["privatenets"]})
            else:
                return []
        return serversInfo