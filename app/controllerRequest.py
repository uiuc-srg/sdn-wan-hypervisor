class ControllerRequest:
    def __init__(self, datapath, vlan_tag, guest_controller_addr, local_address, local_port, guest_controller_port,
                 only_forwarding):
        self.datapath = datapath
        self.vlan_tag = vlan_tag
        self.guest_controller_addr = guest_controller_addr
        self.guest_controller_port = guest_controller_port
        self.local_address = local_address
        self.local_port = local_port
        self.only_forwarding = only_forwarding
