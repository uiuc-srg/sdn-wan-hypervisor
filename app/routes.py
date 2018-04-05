from app import app
from threading import Lock
import enclave
from flask import request, jsonify
import requestBroadcast as RequestBroadcast

port_offset_lock = Lock()
port_offset = 3
import startVPN as StartVPN


@app.route('/')
@app.route('/index')
def index():
    return "Hello, here is the sdn config api!"


# TODO: TRIGER RULE CHANGING WHEN HITTED
@app.route('/port/<offset>', methods=['PUT'])
def define_port_incr(offset):
    port_offset_lock.acquire()
    global port_offset
    port_offset = int(offset)
    port_offset_lock.release()
    return "new port offset set"


def get_port_offset():
    port_offset_lock.acquire()
    offset = port_offset
    port_offset_lock.release()
    return offset


@app.route('/enclave/new', methods=['PUT'])
def create_new_enclave():
    print("new enclave request")
    req = RequestBroadcast.RequestBroadcast()
    serversInfo = req.broadcastNewVPNRequest("10.0.0.0")
    if len(serversInfo) > 0:
        for serverInfo in serversInfo:
            print(serverInfo)
            keyDir = "/home/yuen/Desktop/openvpenca/keys"
            keyName = "client1"
            vpnserver = serverInfo["vpnserver"]
            nextHop = ""
            StartVPN.startServiceVPNClient("10.0.0.12:5000", keyDir, keyName, vpnserver, nextHop)

    new_enclave = enclave.Enclave()
    return str(new_enclave.enclave_id)


@app.route('/vpncreate', methods=['POST'])
def create_new_vpn():
    print("receive new vpn request")
    configs = request.get_json(silent=True)

    keyDir = "/home/yuen/Desktop/openvpenca/keys"
    keyName = "server2"
    subNet = "10.0.201.0"
    vpnserver = "10.0.3.10"
    privatenets = "10.0.2.0,10.0.1.11"
    vpnclients = "client1,10.0.201.5," + configs['subnet']
    StartVPN.startServiceVPNServer("10.0.2.11:5000", keyDir, keyName, subNet, vpnserver, privatenets, vpnclients)
    return jsonify(vpnserver=vpnserver, privatenets=privatenets)
