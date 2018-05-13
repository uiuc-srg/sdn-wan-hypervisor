from app import app
from threading import Lock

from flask import request, jsonify
import enclaveService
import startVPN as StartVPN
import requests
import Queue
import controllerRequest
import json


COMMIT_RETRY_TIMES = 3

service = enclaveService.Service()


@app.route('/')
@app.route('/index')
def index():
    return "Hello, here is the sdn config api!"


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
                                    json={"initiator": service.addr, "enclave_id": new_enclave_id,
                                          "institution_list": [service.addr] + institutions_list})
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
        local_commit_result = service.commit(service.addr, new_enclave_id, [service.addr] + institutions_list)
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
        return "Create vpn mesh failed\n", 400
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
                print "create vpn server failed\n"
                return -1
            else:
                vpn_server_ip = res.json()["vpn_server"]
                client_institution_addr = institutions_list[i]
                if client_institution_addr == "127.0.0.1":
                    res = _create_new_vpn_client(vpn_server_ip, enclave_id)
                    if res == "success":
                        return 0
                    print "create vpn client failed\n"
                    return -1
                else:
                    print vpn_server_ip
                    print client_institution_addr
                    res = requests.post("http://" + client_institution_addr + ":5678/vpn/create_client",
                                        json={"enclave_id": enclave_id, "vpn_server": vpn_server_ip})
                    if res.status_code != 200:
                        print "create vpn client failed\n"
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
    return "unstage success\n"


@app.route('/enclave/commit', methods=['POST'])
def enclave_commit():
    print("new enclave request")
    configs = request.get_json(silent=True)
    initiator = configs["initiator"]
    enclave_id = configs["enclave_id"]
    institution_list = configs["institution_list"]
    result = service.commit(initiator, enclave_id, institution_list)
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

    service.save_enclave_port_to_database(enclave_id, datapath_id, port_number)
    return "port added\n"


def _create_new_vpn_client(vpn_server_ip, enclave_id):
    vpnserver_host_info = service.get_next_vpn_host()
    if vpnserver_host_info is None:
        return "no available vpn hosts\n"

    node_internal_ip = vpnserver_host_info.internal_addr
    node_addr = node_internal_ip + ":5000"
    ca_location = vpnserver_host_info.client_ca_location
    cert_location = vpnserver_host_info.client_cert_location
    key_location = vpnserver_host_info.client_key_location
    dh_location = vpnserver_host_info.client_dh_location
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
        return "no available vpn hosts\n", 404

    vpn_server_ip = configs["vpn_server"]
    enclave_id = int(configs["enclave_id"])
    node_internal_ip = vpnserver_host_info.internal_addr
    node_addr = node_internal_ip + ":5000"
    ca_location = vpnserver_host_info.client_ca_location
    cert_location = vpnserver_host_info.client_cert_location
    key_location = vpnserver_host_info.client_key_location
    dh_location = vpnserver_host_info.client_dh_location
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
        return "success\n"
    else:
        return "create client fail\n", 404


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
    ca_location = vpnserver_host_info.server_ca_location
    cert_location = vpnserver_host_info.server_cert_location
    key_location = vpnserver_host_info.server_key_location
    dh_location = vpnserver_host_info.server_dh_location
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


@app.route('/start_system', methods=['POST'])
def start_system():
    configs = request.get_json(silent=True)
    config_file_path = configs["config_file_path"]
    with open(config_file_path) as data_file:
        system_configs = json.load(data_file)
        primary_switch_hypervisor_port = system_configs["port_to_hypervisor"]
        self_addr = system_configs["hypervisor_address"]
        primary_dpid = system_configs["primary_dpid"]
        primary_switch_down_ports = system_configs["primary_switch_down_ports"]
        hypervisor_OF_port = system_configs["hypervisor_of_port"]
        service.primary_switch_hypervisor_port = primary_switch_hypervisor_port
        service.set_self_addr(self_addr)
        service.primary_datapath = service.datapath_dic[primary_dpid]
        service.primary_switch_down_ports = primary_switch_down_ports

        for switch in system_configs["slave_switches"]:
            dpid = switch["dpid"]
            upport = switch["up_port"]
            down_ports = switch["down_ports"]
            address = switch["address"]
            mac_addr = switch["mac_addr"]
            hyperv_slave_port = switch["hyperv_slave_port"]
            service.append_slave_switch(dpid, upport, service.datapath_dic[dpid], down_ports, address)
            requests.post("http://" + address + ":5000/set_master_controller",
                          json={"address": service.addr, "port": hypervisor_OF_port})
            service.add_slave_switch_direct_rule(mac_addr, -1, hyperv_slave_port, primary_switch_hypervisor_port)
            service.ban_downwards_ports(dpid)

        for host in system_configs["vpn_hosts"]:
            internal_addr = host["internal_addr"]
            public_addr = host["public_addr"]
            privatenet = host["privatenet"]
            switch_port = host["switch_port"]
            mac_addr = host["mac_addr"]
            bridge_int = host["bridge_int"]
            key_dir = host["key_dir"]

            server_ca_location = host["server_ca_location"]
            server_cert_location = host["server_cert_location"]
            server_key_location = host["server_key_location"]
            server_dh_location = host["server_dh_location"]

            client_ca_location = host["client_ca_location"]
            client_cert_location = host["client_cert_location"]
            client_key_location = host["client_key_location"]
            client_dh_location = host["client_dh_location"]

            eth_broadcast_addr = host["eth_broadcast_addr"]
            client_ip_pool_start = host["client_ip_pool_start"]
            client_ip_pool_end = host["client_ip_pool_end"]
            service.append_vpn_hosts(internal_addr, public_addr, privatenet,
                                     switch_port, mac_addr, bridge_int, key_dir,
                                     eth_broadcast_addr, client_ip_pool_start,
                                     client_ip_pool_end, True, server_ca_location, server_cert_location,
                                     server_key_location, server_dh_location, client_ca_location,
                                     client_cert_location, client_key_location, client_dh_location)

        for primary_vpn_host in system_configs["primary_vpn_hosts"]:
            if primary_vpn_host["type"] == "client":
                node_internal_ip = primary_vpn_host["node_internal_ip"]
                vpn_server_ip = primary_vpn_host["vpn_server_ip"]
                key_dir = primary_vpn_host["key_dir"]
                ca_location = primary_vpn_host["ca_location"]
                cert_location = primary_vpn_host["cert_location"]
                key_location = primary_vpn_host["key_location"]
                dh_location = primary_vpn_host["dh_location"]
                bridged_eth_interface = primary_vpn_host["bridged_eth_interface"]
                eth_broadcast_addr = primary_vpn_host["eth_broadcast_addr"]
                hypervisor_ip = primary_vpn_host["hypervisor_ip"]
                switch_port = primary_vpn_host["switch_port"]
                StartVPN.start_service_vpn_client(node_internal_ip + ":5000", node_internal_ip, vpn_server_ip,
                                                  ca_location, cert_location,
                                                  key_location, dh_location, bridged_eth_interface,
                                                  eth_broadcast_addr)
                service.bind_hypervisor_dest_ip_to_port(hypervisor_ip, switch_port)
                service.add_primary_switch_direct_rule(switch_port, primary_switch_hypervisor_port)

            if primary_vpn_host["type"] == "server":
                node_internal_ip = primary_vpn_host["node_internal_ip"]
                node_public_ip = primary_vpn_host["node_public_ip"]
                key_dir = primary_vpn_host["key_dir"]
                ca_location = primary_vpn_host["ca_location"]
                cert_location = primary_vpn_host["cert_location"]
                key_location = primary_vpn_host["key_location"]
                dh_location = primary_vpn_host["dh_location"]
                client_ip_pool_start = primary_vpn_host["client_ip_pool_start"]
                client_ip_pool_stop = primary_vpn_host["client_ip_pool_stop"]
                subnet_behind_server = primary_vpn_host["subnet_behind_server"]
                bridged_eth_interface = primary_vpn_host["bridged_eth_interface"]
                eth_broadcast_addr = primary_vpn_host["eth_broadcast_addr"]
                hypervisor_ip = primary_vpn_host["hypervisor_ip"]
                switch_port = primary_vpn_host["switch_port"]
                StartVPN.start_service_vpn_server(node_internal_ip + ":5000", node_internal_ip, node_public_ip, ca_location,
                                                  cert_location,
                                                  key_location, dh_location, client_ip_pool_start,
                                                  client_ip_pool_stop,
                                                  subnet_behind_server, bridged_eth_interface, eth_broadcast_addr)

                service.bind_hypervisor_dest_ip_to_port(hypervisor_ip, switch_port)
                service.add_primary_switch_direct_rule(switch_port, primary_switch_hypervisor_port)
    return "config loaded\n"


guest_controller_request_queue = Queue.Queue()


@app.route('/enclave/new_controller', methods=['POST'])
def new_controller_request():
    print("receive new controller request")
    configs = request.get_json(silent=True)
    guest_controller_address = configs["guest_controller_address"]
    enclave_id = configs["enclave_id"]
    guest_controller_port = configs["guest_controller_port"]
    connect_to_remote = configs["connect_to_remote"]
    guest_controller_switch_port = configs["guest_controller_switch_port"]
    enclave_item = service.commited_list[enclave_id]
    vlan_tag = enclave_item.vlan_tag
    local_addr = service.addr
    service.bind_hypervisor_dest_ip_to_port(guest_controller_address, guest_controller_switch_port)
    service.add_primary_switch_direct_rule(guest_controller_switch_port, service.primary_switch_hypervisor_port)

    global guest_controller_request_queue
    for (dpid, slave_switch) in service.slave_switch_dic.iteritems():
        switch_addr = slave_switch.address
        next_fake_controller_port = service.get_next_fake_controller_port()
        res = requests.post("http://" + switch_addr + ":5000/new_controller",
                            json={"address": local_addr, "port": next_fake_controller_port})
        if not res.ok:
            return "add new controller to switch failed\n", 400

        controller_request = controllerRequest.ControllerRequest(slave_switch.datapath, vlan_tag,
                                                                 guest_controller_address, local_addr,
                                                                 next_fake_controller_port, guest_controller_port,
                                                                 False)
        guest_controller_request_queue.put(controller_request)

    if not connect_to_remote:
        return "guest controller request queued\n"

    print "connecting to remote institutions"
    print enclave_item.institution_list
    for institution in enclave_item.institution_list:
        if institution != service.addr:
            res = requests.get("http://" + institution + ":5678/enclave/switch_count")
            count = int(res.json()["count"])
            port_list = []
            for i in range(0, count):
                port_list.append(service.get_next_fake_controller_port())

            print "send new controller req to " + institution
            res = requests.post("http://" + institution + ":5678/enclave/new_remote_controller",
                                json={"guest_controller_address": service.addr, "enclave_id": enclave_id,
                                      "guest_controller_ports": port_list,
                                      "connect_to_remote": False})
            if not res.ok:
                return "contact remote institution failed", 400

            for port in port_list:
                controller_request = controllerRequest.ControllerRequest(None, -1,
                                                                         guest_controller_address, local_addr,
                                                                         port,
                                                                         guest_controller_port, True)
                guest_controller_request_queue.put(controller_request)

    return "guest controller request queued\n"


@app.route('/enclave/new_remote_controller', methods=['POST'])
def new_remote_controller_request():
    print("receive new controller request")
    configs = request.get_json(silent=True)
    guest_controller_address = configs["guest_controller_address"]
    enclave_id = configs["enclave_id"]
    guest_controller_port_list = configs["guest_controller_ports"]
    connect_to_remote = configs["connect_to_remote"]
    enclave_item = service.commited_list[enclave_id]
    vlan_tag = enclave_item.vlan_tag
    local_addr = service.addr

    global guest_controller_request_queue
    port_idx = 0
    for (dpid, slave_switch) in service.slave_switch_dic.iteritems():
        switch_addr = slave_switch.address
        next_fake_controller_port = service.get_next_fake_controller_port()
        res = requests.post("http://" + switch_addr + ":5000/new_controller",
                            json={"address": local_addr, "port": next_fake_controller_port})
        if not res.ok:
            return "add new controller to switch failed\n", 400

        controller_request = controllerRequest.ControllerRequest(slave_switch.datapath, vlan_tag,
                                                                 guest_controller_address, local_addr,
                                                                 next_fake_controller_port,
                                                                 int(guest_controller_port_list[port_idx]),
                                                                 False)
        guest_controller_request_queue.put(controller_request)
        port_idx += 1

    if not connect_to_remote:
        return "guest controller request queued\n"


@app.route('/enclave/switch_count', methods=['GET'])
def switch_count():
    print("receive new switch count request")
    return jsonify(count=len(service.slave_switch_dic))


def get_new_guest_controller_request():
    global guest_controller_request_queue
    if not guest_controller_request_queue.empty():
        return guest_controller_request_queue.get()
    return None
