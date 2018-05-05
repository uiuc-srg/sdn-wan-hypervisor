from flask import Flask, request
import os as os
from generateVPNScript import *
app = Flask(__name__)

serviceStarted = False


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/startVPNserver", methods=['POST'])
def start_vpn_server():
    global serviceStarted
    if serviceStarted:
        return "server already stared"
    serviceStarted = True

    configs = request.get_json(silent=True)
    vpn_server_listen_addr = configs["vpn_server_listen_addr"]
    ca_location = configs["ca_location"]
    cert_location = configs["cert_location"]
    key_location = configs["key_location"]
    dh_location = configs["dh_location"]
    bridged_ip = configs['bridged_ip']
    client_ip_pool_start = configs["client_ip_pool_start"]
    client_ip_pool_stop = configs["client_ip_pool_stop"]
    subnet_behind_server = configs["subnet_behind_server"]
    server_config = generate_vpn_server_config(vpn_server_listen_addr, ca_location, cert_location, key_location,
                                               dh_location, bridged_ip, client_ip_pool_start, client_ip_pool_stop,
                                               subnet_behind_server)
    f = open("temp_server_config.conf", "w+")
    f.write(server_config)
    f.close()

    bridged_eth_interface = configs["bridged_eth_interface"]
    eth_ip = configs["eth_ip"]
    eth_broadcast_addr = configs["eth_broadcast_addr"]
    bridge_start_script = generate_start_script(bridged_eth_interface, eth_ip, eth_broadcast_addr,
                                                "temp_server_config.conf")

    f2 = open("temp_server_start.sh", "w+")
    f2.write(bridge_start_script)
    f2.close()
    os.system("sh temp_server_start.sh")
    # os.system("nohup openvpn --config temp_server_config.conf")

    return "vpn server started\n"


@app.route("/startVPNClient", methods=['POST'])
def start_vpn_client():
    global serviceStarted
    if serviceStarted:
        return "client already stared"
    serviceStarted = True

    configs = request.get_json(silent=True)
    vpn_server_ip = configs["vpn_server_ip"]
    ca_location = configs["ca_location"]
    cert_location = configs["cert_location"]
    key_location = configs["key_location"]
    dh_location = configs["dh_location"]
    client_config = generate_vpn_client_config(vpn_server_ip, ca_location, cert_location, key_location, dh_location)
    f1 = open("temp_client_config.conf", "w+")
    f1.write(client_config)
    f1.close()

    bridged_eth_interface = configs["bridged_eth_interface"]
    eth_ip = configs["eth_ip"]
    eth_broadcast_addr = configs["eth_broadcast_addr"]
    bridge_start_script = generate_start_script(bridged_eth_interface, eth_ip, eth_broadcast_addr,
                                                "temp_client_config.conf")

    f2 = open("temp_client_start.sh", "w+")
    f2.write(bridge_start_script)
    f2.close()
    os.system("sh temp_client_start.sh")
    # os.system("nohup openvpn --config temp_client_config.conf")
    return "vpn client started\n"


@app.route("/stopVPNService")
def stop_vpn_service():
    os.system("killall -SIGINT openvpn")
    return "stopped"
