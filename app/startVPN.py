import os as os
import requests


def init_switch_ip(ip_addr, subnet_mask):
    command = "ifconfig ovsbr0 " + ip_addr + "/" + str(subnet_mask) + " up"
    print (command)
    os.system(command)
    os.system("route -n")


def start_service_vpn_server(node_addr, node_internal_ip, node_public_ip, ca_location, cert_location, key_location,
                             dh_location, client_ip_pool_start, client_ip_pool_stop, subnet_behind_server,
                             bridged_eth_interface, eth_broadcast_addr):
    # vpn_server_listen_addr, ca_location, cert_location, key_location,
    # dh_location, bridged_ip, client_ip_pool_start, client_ip_pool_stop,
    # subnet_behind_server
    # bridged_eth_interface, eth_ip, eth_broadcast_addr

    # os.system("route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.2.10")
    # os.system("route add -net 10.0.200.0 netmask 255.255.255.0 gw 10.0.2.10")
    res = requests.post("http://" + node_addr + '/startVPNserver',
                        json={"vpn_server_listen_addr": node_public_ip,
                              "ca_location": ca_location,
                              "cert_location": cert_location,
                              "key_location": key_location,
                              "dh_location": dh_location,
                              "bridged_ip": node_internal_ip,
                              "client_ip_pool_start": client_ip_pool_start,
                              "client_ip_pool_stop": client_ip_pool_stop,
                              "subnet_behind_server": subnet_behind_server,
                              "bridged_eth_interface": bridged_eth_interface,
                              "eth_ip": node_internal_ip,
                              "eth_broadcast_addr": eth_broadcast_addr
                              })
    if res.ok:
        print("server start request sent")
        return True
    else:
        return False


def start_service_vpn_client(node_addr, node_internal_ip, vpn_server_ip, ca_location, cert_location, key_location,
                             dh_location, bridged_eth_interface, eth_broadcast_addr):
    # vpn_server_ip, ca_location, cert_location, key_location, dh_location
    # bridged_eth_interface, eth_ip, eth_broadcast_addr
    res = requests.post("http://" + node_addr + '/startVPNClient',
                        json={"vpn_server_ip": vpn_server_ip,
                              "ca_location": ca_location,
                              "cert_location": cert_location,
                              "key_location": key_location,
                              "dh_location": dh_location,
                              "bridged_eth_interface": bridged_eth_interface,
                              "eth_ip": node_internal_ip,
                              "eth_broadcast_addr": eth_broadcast_addr,
                              })
    if res.ok:
        print("client start request sent")
        return True
    else:
        return False


def stop_service_vpn(node_addr):
    res = requests.post("http://" + node_addr + '/stopVPNService')
    if res.ok:
        print("stop request sent")
        return True
    else:
        return False
