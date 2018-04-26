import datetime


class Enclave:
    def __init__(self, enclave_id, initiator_addr, committed=False, vlan_tag=-1):
        self.enclave_id = enclave_id
        self.vlan_tag = vlan_tag
        self.committed = committed
        self.initiator_addr = initiator_addr
        self.created_time = datetime.datetime.now()
        self.vpn_host = None
        self.reachable_subnets = []

        # TODO create a class that can contain more info than just the port number
        self.switch_ports = []

    def set_vpn_host(self, vpn_host):
        self.vpn_host = vpn_host

    def append_enclave_switch_port(self, port):
        self.switch_ports.append(port)

    def append_reachable_subnet(self, subnet):
        self.reachable_subnets.append(subnet)