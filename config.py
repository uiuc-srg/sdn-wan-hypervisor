from jinja2 import Template
from generateVPNScript import *

class HypervisorConfig:
    def __init__(self):
        self.enclaveVPNServers = []
        self.enclaveVPNClients = []
        self.nextEnclaveVPNServerIdx = 0
        self.nextEnclaveVPNClientIdx = 0

    def generateMainVPNServerConfig(self, filename):
        keyDir = "/home/yuen/Desktop/openvpenca/keys"
        keyName = "server2"
        subNet = "10.0.200.0"
        vpnserver = "10.0.1.11"
        privatenets = "10.0.2.0,10.0.1.11"
        vpnclients = "client1,10.0.200.5,10.0.0.0"
        config = generate_vpn_server_config(keyDir, keyName, subNet, vpnserver, privatenets, vpnclients)

        f = open(filename, "w+")
        f.write(config)
        f.close()
        return vpnserver


    def generateMainVPNClientConfig(self, serverAddr, filename):
        keyDir = "/home/yuen/Desktop/openvpenca/keys"
        keyName = "client1"
        vpnserver = serverAddr
        nextHop = ""
        clientconfig = generate_vpn_client_config(keyDir, keyName, vpnserver, nextHop)

        f = open(filename, "w+")
        f.write(clientconfig)
        f.close()

        vpnClientAddr = "10.0.0.11"
        return

    def generateNextEnclaveServer(self, fileName):
        keyDir = "/home/yuen/Desktop/openvpenca/keys"
        keyName = "server2"
        subNet = "10.0.200.0"
        vpnserver = "10.0.0.11"
        privatenets = "10.0.1.0,10.0.0.11"
        vpnclients = ""
        config = generate_vpn_server_config(keyDir, keyName, subNet, vpnserver, privatenets, vpnclients)

        f = open(fileName, "w+")
        f.write(config)
        f.close()




    def generateNextEnclaveClient(self, fileName, serverAddr):
        keyDir = "/home/yuen/Desktop/openvpenca/keys"
        keyName = "client1"
        vpnserver = serverAddr
        nextHop = ""
        clientconfig = generate_vpn_client_config(keyDir, keyName, vpnserver, nextHop)

        f = open(fileName, "w+")
        f.write(clientconfig)
        f.close()

