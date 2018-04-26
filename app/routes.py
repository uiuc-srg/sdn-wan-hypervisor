from app import app
from threading import Lock

from flask import request, jsonify
import enclaveService
import startVPN as StartVPN
import requests

COMMIT_RETRY_TIMES = 3

port_offset_lock = Lock()
port_offset = 3
service = enclaveService.Service()


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


def set_self_addr(addr):
    service.set_self_addr(addr)


def set_datapath(datapath):
    service.set_datapath(datapath)


def append_vpn_host_list(internal_addr, public_addr, privatenets_str, available, switch_port, mac_addr):
    service.append_vpn_hosts(internal_addr, public_addr, privatenets_str, available, switch_port, mac_addr)

# @app.route('/enclave/new', methods=['POST'])
# def create_new_enclave():
#     print("new enclave request")
#     serversInfo = RequestBroadcast.broadcastNewVPNRequest("10.0.0.0")
#     if len(serversInfo) > 0:
#         for serverInfo in serversInfo:
#             print(serverInfo)
#             keyDir = "/home/yuen/Desktop/openvpenca/keys"
#             keyName = "client1"
#             vpnserver = serverInfo["vpnserver"]
#             nextHop = ""
#             StartVPN.startServiceVPNClient("10.0.0.12:5000", keyDir, keyName, vpnserver, nextHop)
#
#     new_enclave = enclave.Enclave()
#     return str(new_enclave.enclave_id)

# {institutions:a, b, c}
@app.route('/enclave/new', methods=['POST'])
def create_new_enclave():
    print("new enclave request")
    configs = request.get_json(silent=True)
    # TODO ADD A DEFAULT OPTION
    institutions_list = configs["institutions"].split(",")
    result = ""
    if len(institutions_list) < 0:
        return "no institutions provided\n", 400

    stage_success = True
    service.stage(service.addr)
    for institution in institutions_list:
        print(institution)
        res = requests.post("http://" + institution + ":5678/enclave/stage", json={"initiator": service.addr})
        if res.status_code == 400:
            result = "requested institution already staged\n"
            stage_success = False

    commit_success = False
    new_enclave_id = service.peak_next_enclave_id()
    print "purposed enclave id" + str(new_enclave_id)
    if stage_success:
        highest_enclave_id = -1
        retry_times = 0
        while retry_times <= COMMIT_RETRY_TIMES:
            commit_success = True
            if highest_enclave_id > new_enclave_id:
                new_enclave_id = highest_enclave_id
            retry_times += 1
            no_roll_back_list = []
            for idx in range(len(institutions_list)):
                res = requests.post("http://" + institutions_list[idx] + ":5678/enclave/commit", json={"initiator": service.addr, "enclave_id": new_enclave_id})
                if res.status_code != 200:
                    print res.content
                    print res.status_code
                    no_roll_back_list.append(institutions_list[idx])
                    commit_success = False
                if res.status_code == 406:
                    suggested_enclave_id = int(res.json()["suggested_enclave_id"])
                    if suggested_enclave_id > highest_enclave_id:
                        highest_enclave_id = suggested_enclave_id
                if res.status_code == 400:
                    retry_times = COMMIT_RETRY_TIMES + 1
            if not commit_success:
                for institution in institutions_list:
                    if institution not in no_roll_back_list:
                        requests.post("http://" + institution + ":5678/enclave/roll_back", json={"enclave_id": new_enclave_id})
            else:
                break
    print("commit process done")

    if commit_success:
        # result = str(new_enclave_id) + "\n"
        local_commit_result = service.commit(service.addr, new_enclave_id)
        if local_commit_result != enclaveService.COMMIT_SUCCESS:
            result = "local commit fail with fail number" + str(local_commit_result) + "\n"
            commit_success = False
        else:
            result = str(new_enclave_id) + "\n"

    service.unstage(service.addr)
    for institution in institutions_list:
        requests.post("http://" + institution + ":5678/enclave/unstage", json={"initiator": service.addr})
    print("unstage all process done")

    if commit_success:
        return result, 200
    else:
        return result, 400


@app.route('/enclave/stage', methods=['POST'])
def enclave_stage():
    print("new stage request")
    configs = request.get_json(silent=True)
    initiator = configs["initiator"]
    stage_result = service.stage(initiator)
    if stage_result == enclaveService.STAGE_SUCCESS:
        return "stage success"
    else:
        return "stage not success", 400

@app.route('/enclave/unstage', methods=['POST'])
def enclave_unstage():
    print("new unstage request")
    configs = request.get_json(silent=True)
    initiator = configs["initiator"]
    service.unstage(initiator)
    return "unstage success"


@app.route('/enclave/commit', methods=['POST'])
def enclave_commit():
    print("new enclave request")
    configs = request.get_json(silent=True)
    initiator = configs["initiator"]
    enclave_id = configs["enclave_id"]
    result = service.commit(initiator, enclave_id)
    print result
    if result == enclaveService.COMMIT_SUCCESS:
        return "commit success", 200
    elif result == enclaveService.COMMIT_FAIL_NO_ENOUGH_VLAN:
        return "not enough vlan", 400
    elif result == enclaveService.COMMIT_FAIL_NOT_IN_STAGE:
        return "not in stage", 400
    else:
        return jsonify(suggested_enclave_id=result), 406


@app.route('/enclave/roll_back', methods=['POST'])
def enclave_rollback():
    print("new enclave request")
    configs = request.get_json(silent=True)
    enclave_id = configs["enclave_id"]
    service.roll_back_commit(enclave_id)


@app.route('/enclave/add_port', methods=['POST'])
def add_port_to_enclave():
    configs = request.get_json(silent=True)
    enclave_id = configs["enclave_id"]
    port_number = int(configs["switch_port"])
    res = service.add_port_to_enclave(port_number, enclave_id)
    if res != enclaveService.SUCCESS:
        return "adding port failed, error code :" + res, 400
    return "ports added"

# # {institution_a: a, institution_b: b, institution_a_subnet:, institution_b_subnet:, enclave_id: id}
# @app.route('/enclave/connect', methods=['POST'])
# def enclave_connect():
#     print("new enclave request")
#     configs = request.get_json(silent=True)
#     institution_a = configs["institution_a"]
#     institution_b = configs["institution_b"]
#     institution_a_subnet = configs["institution_a_subnet"]
#     institution_b_subnet = configs["institution_b_subnet"]
#     enclave_id = configs["enclave_id"]
#     res = requests.post("http://" + institution_a + "/vpn/create_server", json={"enclave_id": enclave_id, "subnets":institution_b_subnet})
#     if not res.ok:
#         return res.content
#
#     vpnServerInfo = res.json()
#     server_addr = vpnServerInfo["vpnserver"]
#     server_subnets = vpnServerInfo["privatenets"]
#     res = requests.post("http://" + institution_b + "/vpn/create_client",
#                         json={"enclave_id": enclave_id, "subnets": server_subnets, "server_addr": server_addr})
#     if not res.ok:
#         # TODO: RELEASE RESOURCE WHEN FAIL
#         # res = requests.post("http://" + institution_a + "/vpn/stop_vpn",
#         #                     json={"enclave_id": enclave_id, "addr": institution_b_subnet})
#         return "create connection fail", 404
#     return "success"

@app.route('/vpn/create_client', methods=['POST'])
def create_new_vpn_client():
    print("receive new vpn request")
    configs = request.get_json(silent=True)

    key_dir = "/home/yuen/Desktop/openvpenca/keys"
    key_name = "client1"
    vpnserver = configs["vpn_server"]
    reachable_subnets = configs["reachable_subnets"]
    nextHop = ""
    vpnserver_host_info = service.get_next_vpn_host()
    if vpnserver_host_info is None:
        return "no available vpn hosts", 404
    host_private_addr = vpnserver_host_info.internal_addr
    host_public_addr = vpnserver_host_info.public_addr
    enclave_id = int(configs["enclave_id"])
    res = StartVPN.startServiceVPNClient(host_private_addr+":5000", key_dir, key_name, vpnserver, nextHop)
    service.save_vpn_client_to_database(enclave_id, host_public_addr, host_private_addr, key_dir, key_name, vpnserver, nextHop)
    service.set_enclave_vpn_map(enclave_id, vpnserver_host_info)
    service.bind_enclave_vpn(enclave_id, reachable_subnets)
    if res:
        return "success"
    else:
        return "create client fail", 404


# @app.route('/vpn/bind_enclave_vpn', methods=['POST'])
# def bind_enclave_vpn():
#     print("receive new bind request")
#


# take subnet for client and enclaveid id
@app.route('/vpn/create_server', methods=['POST'])
def create_new_vpn_server():
    print("receive new vpn request")
    configs = request.get_json(silent=True)
    vpnserver_host_info = service.get_next_vpn_host()
    if vpnserver_host_info is None:
        return "no available vpn hosts", 404
    key_dir = "/home/yuen/Desktop/openvpenca/keys"
    key_name = "server2"
    subnet = "10.0.201.0"
    host_public_addr = vpnserver_host_info.public_addr
    privatenets = vpnserver_host_info.privatenets
    host_private_addr = vpnserver_host_info.internal_addr
    # TODO add supports for more clients
    vpnclients = "client1,10.0.201.5," + configs['subnet']
    enclave_id = int(configs['enclave_id'])
    reachable_subnets = configs["reachable_subnets"]
    res = StartVPN.startServiceVPNServer(host_private_addr+":5000", key_dir, key_name, subnet, host_public_addr, privatenets, vpnclients)
    service.save_vpn_server_to_database(enclave_id, key_dir, key_name, subnet, host_public_addr, privatenets, vpnclients, host_private_addr)
    service.set_enclave_vpn_map(enclave_id, vpnserver_host_info)
    # TODO: PUSH THE RULE TO Openflow table
    service.bind_enclave_vpn(enclave_id, reachable_subnets)
    if res:
        return jsonify(vpnserver=host_public_addr, privatenets=privatenets)
    else:
        return "create server fail", 404


@app.route('/vpn/stop_vpn', methods=['POST'])
def stop_vpn():
    print("receive vpn stop request")


@app.route('/enclave/list', methods=['GET'])
def enclave_list():
    print("new enclave request")
    return service.get_commited_enclaves()


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


# TODO: ADD ENDPOINT TO ADD PYHSICAL POINT TO THE ENCLAVE

