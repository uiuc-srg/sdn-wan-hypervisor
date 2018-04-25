import datetime


class Enclave:
    def __init__(self, enclave_id, initiator_addr, committed=False, vlan_tag=-1):
        self.enclave_id = enclave_id
        self.vlan_tag = vlan_tag
        self.committed = committed
        self.initiator_addr = initiator_addr
        self.created_time = datetime.datetime.now()
        self.vpn_host = None

    def set_vpn_host(self, vpn_host):
        self.vpn_host = vpn_host
