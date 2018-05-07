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


def append_datapath(datapath_id, datapath):
    service.append_datapath(datapath_id, datapath)


def append_vpn_host_list(internal_addr, public_addr, privatenet, switch_port, mac_addr, bridge_int, key_dir,
                         eth_broadcast_addr, client_ip_pool_start, client_ip_pool_end, available):
    service.append_vpn_hosts(internal_addr, public_addr, privatenet, switch_port, mac_addr, bridge_int, key_dir,
                             eth_broadcast_addr, client_ip_pool_start, client_ip_pool_end, available)


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
    # TODO: SAVE institution LIST TO DATABASE AND ENCLAVE CLASS
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
                res = requests.post("http://" + institutions_list[idx] + ":5678/enclave/commit",
                                    json={"initiator": service.addr, "enclave_id": new_enclave_id})
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
                        requests.post("http://" + institution + ":5678/enclave/roll_back",
                                      json={"enclave_id": new_enclave_id})
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
        res = create_vpn_mesh(["127.0.0.1"] + institutions_list, new_enclave_id)
        if res == 0:
            return result, 200
        return "Create vpn mesh failed", 400
    else:
        return result, 400


def create_vpn_mesh(institutions_list, enclave_id):
    institution_count = len(institutions_list)
    for i in range(0, institution_count):
        for j in range(i + 1, institution_count):
            server_institution_addr = institutions_list[j]
            res = requests.post("http://" + server_institution_addr + ":5678/vpn/create_server",
                                json={"enclave_id": enclave_id})
            if res.status_code != 200:
                return -1
            else:
                vpn_server_ip = res.json()["vpn_server"]
                client_institution_addr = institutions_list[i]
                if client_institution_addr == "127.0.0.1":
                    res = _create_new_vpn_client(vpn_server_ip, enclave_id)
                    if res == "success":
                        return 0
                    return -1
                else:
                    print vpn_server_ip
                    print client_institution_addr
                    res = requests.post("http://" + client_institution_addr + ":5678/vpn/create_client",
                                        json={"enclave_id": enclave_id, "vpn_server": vpn_server_ip})
                    if res.status_code != 200:
                        return -1
    return 0


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
    datapath_id = int(configs["datapath_id"])
    res = service.bind_slave_switch_port_to_vlan(datapath_id, enclave_id, port_number)
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
#     res = requests.post("http://" + institution_a + "/vpn/create_server",
# json={"enclave_id": enclave_id, "subnets":institution_b_subnet})
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
def _create_new_vpn_client(vpn_server_ip, enclave_id):
    vpnserver_host_info = service.get_next_vpn_host()
    if vpnserver_host_info is None:
        return "no available vpn hosts"

    node_internal_ip = vpnserver_host_info.internal_addr
    node_addr = node_internal_ip + ":5000"
    ca_location = vpnserver_host_info.key_dir + "ca.crt"
    cert_location = vpnserver_host_info.key_dir + "client1.crt"
    key_location = vpnserver_host_info.key_dir + "client1.key"
    dh_location = vpnserver_host_info.key_dir + "dh2048.pem"
    bridged_eth_interface = vpnserver_host_info.bridge_int
    eth_broadcast_addr = vpnserver_host_info.eth_broadcast_addr

    res = StartVPN.start_service_vpn_client(node_addr, node_internal_ip, vpn_server_ip, ca_location, cert_location,
                                            key_location, dh_location, bridged_eth_interface, eth_broadcast_addr)

    # service.save_vpn_client_to_database(enclave_id, host_public_addr, host_private_addr, key_dir, key_name, vpnserver,
    #                                     nextHop)
    print "vpn request sent\n"
    service.set_enclave_vpn_map(enclave_id, vpnserver_host_info)
    print "binding enclave at primary switch\n"
    service.add_vlan_to_primary_switch(enclave_id)
    if res:
        return "success"
    else:
        return "create client fail"


@app.route('/vpn/create_client', methods=['POST'])
def create_new_vpn_client():
    print("receive new vpn request")
    configs = request.get_json(silent=True)

    vpnserver_host_info = service.get_next_vpn_host()
    if vpnserver_host_info is None:
        print "========================no available vpn hosts"
        return "no available vpn hosts", 404

    vpn_server_ip = configs["vpn_server"]
    enclave_id = int(configs["enclave_id"])
    node_internal_ip = vpnserver_host_info.internal_addr
    node_addr = node_internal_ip + ":5000"
    ca_location = vpnserver_host_info.key_dir + "ca.crt"
    cert_location = vpnserver_host_info.key_dir + "client1.crt"
    key_location = vpnserver_host_info.key_dir + "client1.key"
    dh_location = vpnserver_host_info.key_dir + "dh2048.pem"
    bridged_eth_interface = vpnserver_host_info.bridge_int
    eth_broadcast_addr = vpnserver_host_info.eth_broadcast_addr

    res = StartVPN.start_service_vpn_client(node_addr, node_internal_ip, vpn_server_ip, ca_location, cert_location,
                                            key_location, dh_location, bridged_eth_interface, eth_broadcast_addr)

    # service.save_vpn_client_to_database(enclave_id, host_public_addr, host_private_addr, key_dir, key_name, vpnserver,
    #                                     nextHop)
    print "vpn request sent\n"
    service.set_enclave_vpn_map(enclave_id, vpnserver_host_info)
    print "binding enclave at primary switch\n"
    service.add_vlan_to_primary_switch(enclave_id)
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

    enclave_id = int(configs['enclave_id'])
    node_internal_ip = vpnserver_host_info.internal_addr
    node_addr = node_internal_ip + ":5000"
    node_public_ip = vpnserver_host_info.public_addr
    ca_location = vpnserver_host_info.key_dir + "ca.crt"
    cert_location = vpnserver_host_info.key_dir + "server2.crt"
    key_location = vpnserver_host_info.key_dir + "server2.key"
    dh_location = vpnserver_host_info.key_dir + "dh2048.pem"
    client_ip_pool_start = vpnserver_host_info.client_ip_pool_start
    client_ip_pool_stop = vpnserver_host_info.client_ip_pool_end
    subnet_behind_server = vpnserver_host_info.subnet
    bridged_eth_interface = vpnserver_host_info.bridge_int
    eth_broadcast_addr = vpnserver_host_info.eth_broadcast_addr

    res = StartVPN.start_service_vpn_server(node_addr, node_internal_ip, node_public_ip, ca_location, cert_location,
                                            key_location,
                                            dh_location, client_ip_pool_start, client_ip_pool_stop,
                                            subnet_behind_server,
                                            bridged_eth_interface, eth_broadcast_addr)
    # service.save_vpn_server_to_database(enclave_id, key_dir, key_name, subnet, host_public_addr, privatenets,
    #                                     vpnclients, host_private_addr)
    service.set_enclave_vpn_map(enclave_id, vpnserver_host_info)
    service.add_vlan_to_primary_switch(enclave_id)
    if res:
        return jsonify(vpn_server=node_public_ip, privatenets=subnet_behind_server)
    else:
        return "create server fail", 404


@app.route('/vpn/stop_vpn', methods=['POST'])
def stop_vpn():
    print("receive vpn stop request")


@app.route('/vpn/hosts', methods=['GET'])
def show_vpn():
    service.print_vpn_hosts()
    return "printed"


@app.route('/enclave/list', methods=['GET'])
def enclave_list():
    print("new enclave request")
    return service.get_commited_enclaves()


# @app.route('/vpncreate', methods=['POST'])
# def create_new_vpn():
#     print("receive new vpn request")
#     configs = request.get_json(silent=True)
#
#     keyDir = "/home/yuen/Desktop/openvpenca/keys"
#     keyName = "server2"
#     subNet = "10.0.201.0"
#     vpnserver = "10.0.3.10"
#     privatenets = "10.0.2.0,10.0.1.11"
#     vpnclients = "client1,10.0.201.5," + configs['subnet']
#     StartVPN.startServiceVPNServer("10.0.2.11:5000", keyDir, keyName, subNet, vpnserver, privatenets, vpnclients)
#     return jsonify(vpnserver=vpnserver, privatenets=privatenets)

# TODO: ADD ENDPOINT TO ADD PYHSICAL POINT TO THE ENCLAVE


@app.route('/start_system', methods=['POST'])
def start_system():
    configs = request.get_json(silent=True)
    institution_id = int(configs['institution_id'])
    if institution_id == 1:
        service.primary_datapath = service.datapath_dic[11141121]
        service.primary_switch_down_ports = [1, 3]
        service.append_slave_switch(11141120, 1, service.datapath_dic[11141120], [3, 5])
        service.append_slave_switch(11141123, 1, service.datapath_dic[11141123], [3, 5])

        service.append_vpn_hosts("10.0.0.12", "10.0.1.11", "10.0.0.0", 9, "00:00:00:aa:00:09", "eth0",
                                 "/home/yuen/Desktop/openvpenca/keys/", "10.0.0.255", "10.0.0.50",
                                 "10.0.0.100", True)

        service.append_vpn_hosts("10.0.0.22", "10.0.1.14", "10.0.0.0", 11, " 00:00:00:aa:00:25", "eth0",
                                 "/home/yuen/Desktop/openvpenca/keys/", "10.0.0.255", "10.0.0.50",
                                 "10.0.0.100", True)

        node_internal_ip = "10.0.0.11"
        vpn_server_ip = "10.0.1.12"
        key_dir = "/home/yuen/Desktop/openvpenca/keys/"
        ca_location = key_dir + "ca.crt"
        cert_location = key_dir + "client1.crt"
        key_location = key_dir + "client1.key"
        dh_location = key_dir + "dh2048.pem"
        bridged_eth_interface = "eth0"
        eth_broadcast_addr = "10.0.0.255"

        StartVPN.start_service_vpn_client("10.0.0.11:5000", node_internal_ip, vpn_server_ip, ca_location, cert_location,
                                          key_location, dh_location, bridged_eth_interface, eth_broadcast_addr)
        service.add_primary_switch_direct_rule(7, 5)

        service.ban_downwards_ports(11141120)
        service.ban_downwards_ports(11141123)
        print "primary vpn channel built"
        return "institution 1 stat"

    if institution_id == 2:
        service.primary_datapath = service.datapath_dic[11141135]
        service.primary_switch_down_ports = [5, 7]
        service.append_slave_switch(11141141, 1, service.datapath_dic[11141141], [3, 5])
        service.append_slave_switch(11141139, 1, service.datapath_dic[11141139], [3, 5])

        service.append_vpn_hosts("10.0.0.15", "10.0.1.13", "10.0.0.0", 3, "00:00:00:aa:00:11", "eth1",
                                 "/home/yuen/Desktop/openvpenca/keys/", "10.0.0.255", "10.0.0.50",
                                 "10.0.0.100", True)

        service.append_vpn_hosts("10.0.0.23", "10.0.1.15", "10.0.0.0", 11, "00:00:00:aa:00:28", "eth1",
                                 "/home/yuen/Desktop/openvpenca/keys/", "10.0.0.255", "10.0.0.50",
                                 "10.0.0.100", True)

        # node_addr, node_internal_ip, node_public_ip, ca_location, cert_location, key_location,
        #                          dh_location, client_ip_pool_start, client_ip_pool_stop, subnet_behind_server,
        #                          bridged_eth_interface, eth_broadcast_addr
        node_internal_ip = "10.0.0.14"
        node_public_ip = "10.0.1.12"
        key_dir = "/home/yuen/Desktop/openvpenca/keys/"
        ca_location = key_dir + "ca.crt"
        cert_location = key_dir + "server2.crt"
        key_location = key_dir + "server2.key"
        dh_location = key_dir + "dh2048.pem"
        client_ip_pool_start = "10.0.0.50"
        client_ip_pool_stop = "10.0.0.100"
        subnet_behind_server = "10.0.0.0"
        bridged_eth_interface = "eth1"
        eth_broadcast_addr = "10.0.0.255"
        print "sending vpn create request"
        StartVPN.start_service_vpn_server("10.0.0.14:5000", node_internal_ip, node_public_ip, ca_location,
                                          cert_location,
                                          key_location, dh_location, client_ip_pool_start, client_ip_pool_stop,
                                          subnet_behind_server, bridged_eth_interface, eth_broadcast_addr)
        service.add_primary_switch_direct_rule(1, 9)

        service.ban_downwards_ports(11141141)
        service.ban_downwards_ports(11141139)
        print "primary vpn channel built"
        return "institution 2 stat"

    if institution_id == 3:
        pass
