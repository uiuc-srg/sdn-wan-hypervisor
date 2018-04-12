from flask import Flask, request
app = Flask(__name__)
import os as os
from generateVPNScript import *

serviceStarted = False

@app.route("/")
def hello():
    return "Hello World!"


@app.route("/startVPNserver", methods=['POST'])
def startVPNServer():
    global serviceStarted
    if serviceStarted:
        return "server already stared"
    serviceStarted = True

    configs = request.get_json(silent=True)
    keyDir = configs['keyDir']
    keyName = configs['keyName']
    subNet = configs['subnet']
    vpnserver = configs['vpnserver']
    privatenets = configs["privatenets"]
    vpnclients = configs["vpnclients"]
    config = generateVPNServerScript(keyDir, keyName, subNet, vpnserver, privatenets, vpnclients)

    f = open("serverConfig.sh", "w+")
    f.write(config)
    f.close()
    os.system("sh serverConfig.sh")
    return "started\n"


@app.route("/startVPNClient", methods=['POST'])
def startVPNClient():
    global serviceStarted
    if serviceStarted:
        return "client already stared"
    serviceStarted = True

    configs = request.get_json(silent=True)
    keyDir = configs['keyDir']
    keyName = configs['keyName']
    vpnserver = configs['vpnserver']
    nextHop = configs['nextHop']
    clientconfig = generateVPNClientScript(keyDir, keyName, vpnserver, nextHop)

    f = open("clientConfig.sh", "w+")
    f.write(clientconfig)
    f.close()
    os.system("sh clientConfig.sh")
    return "started\n"


@app.route("/stopVPNService")
def stopVPNService():
    os.system("killall -SIGINT openvpn")
    return "stopped"
