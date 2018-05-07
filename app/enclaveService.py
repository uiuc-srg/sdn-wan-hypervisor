from threading import Lock
import time
import enclave

import sqlite3

SUCCESS = 0
STAGE_SUCCESS = 0
STAGE_FAIL_INTRANSACTION = -1
COMMIT_SUCCESS = 0
COMMIT_FAIL = -1
COMMIT_FAIL_NOT_IN_STAGE = -1
COMMIT_FAIL_NO_ENOUGH_VLAN = -2
ENCLAVE_ID_NOT_COMMITTED = -1
ENCLAVE_HAS_NO_VPN_ASSIGNED = -2


class VpnHostInfo:
    def __init__(self, internal_addr, public_addr, privatenet, switch_port, mac_addr, bridge_int, key_dir,
                 eth_broadcast_addr, client_ip_pool_start, client_ip_pool_end, available):
        self.available = available
        self.internal_addr = internal_addr
        self.public_addr = public_addr
        self.switch_port = switch_port
        # TODO: CONSIDER TO REMOVE THIS AS THE SUBNET SHOULD BE KNOWN ONLY AFTER THE ENCLAVE AND DHCP IS SET
        self.subnet = privatenet
        self.mac_addr = mac_addr
        self.bridge_int = bridge_int
        self.key_dir = key_dir
        self.eth_broadcast_addr = eth_broadcast_addr
        self.client_ip_pool_start = client_ip_pool_start
        self.client_ip_pool_end = client_ip_pool_end


class SwitchInfo:
    def __init__(self, dpid, upwards_port, datapath, downwards_ports):
        self.dpid = dpid
        self.upwards_port = upwards_port
        self.is_primary = False
        self.datapath = datapath
        self.enclave_ports_dic = {}
        self.downwards_ports = downwards_ports
        self.is_enclave_group_set = {}


class Service:
    def __init__(self):
        self.next_enclave_ID = 1
        # enclaveID: enclave
        self.commited_list = {}
        self.update_lock = Lock()
        self.in_transaction = False
        self.available_vlan_tags = {}
        for i in range(0, 4097):
            self.available_vlan_tags[i] = True
        self.vpn_hosts = []
        self.seq = 0
        self.addr = ""
        self.transaction_initiator = ""
        self.stage_begin_time = time.time()
        self.subnets = ""
        self.db_conn = self.init_database()
        # self.enclave_vpn_map = {}
        self.datapath_dic = {}
        self.primary_datapath = None
        self.is_primary_switch_enclave_group_set = {}
        self.primary_switch_down_ports = []
        self.slave_switch_dic = {}

    def append_slave_switch(self, dpid, port, datapath, downwards_ports):
        self.slave_switch_dic[dpid] = SwitchInfo(dpid, port, datapath, downwards_ports)

    def append_datapath(self, datapath_id, datapath):
        self.datapath_dic[datapath_id] = datapath

    def get_datapath(self, datapath_id):
        return self.datapath_dic[datapath_id]

    def set_self_addr(self, addr):
        self.addr = addr

    def get_next_vpn_host(self):
        self.update_lock.acquire()
        next_host = None
        for host in self.vpn_hosts:
            if host.available:
                # print host.public_addr
                # print host.available
                next_host = host
                host.available = False
                break
        self.update_lock.release()
        return next_host

    def print_vpn_hosts(self):
        for host in self.vpn_hosts:
            print host.public_addr
            print host.available

    def set_enclave_vpn_map(self, enclave_id, vpn_host):
        # TODO: MAYBE ADD A LOCK HERE
        # self.enclave_vpn_map[enclave_id] = vpn_host
        # TODO: Check the set vpn here
        self.commited_list[enclave_id].append_vpn_host(vpn_host)

    # def get_enclave_vpn(self, enclave_id):
    #     # TODO: MAYBE ADD A LOCK HERE
    #     return self.enclave_vpn_map[enclave_id]

    def append_vpn_hosts(self, internal_addr, public_addr, privatenet, switch_port, mac_addr, bridge_int, key_dir,
                         eth_broadcast_addr, client_ip_pool_start, client_ip_pool_end, available):
        self.update_lock.acquire()
        entry = VpnHostInfo(internal_addr, public_addr, privatenet, switch_port, mac_addr, bridge_int, key_dir,
                            eth_broadcast_addr, client_ip_pool_start, client_ip_pool_end, available)
        self.vpn_hosts.append(entry)
        print self.vpn_hosts
        self.update_lock.release()

    def stage(self, initiator):
        result = STAGE_SUCCESS
        self.update_lock.acquire()
        if self.in_transaction:
            if time.time() - self.stage_begin_time > 20:
                self.in_transaction = False
            result = STAGE_FAIL_INTRANSACTION
        else:
            self.in_transaction = True
            self.transaction_initiator = initiator
            self.stage_begin_time = time.time()
        self.update_lock.release()
        return result

    def unstage(self, initiator):
        self.update_lock.acquire()
        if initiator == self.transaction_initiator:
            self.in_transaction = False
        self.update_lock.release()

    def commit(self, initiator, enclave_id):
        result = 0
        self.update_lock.acquire()
        if not self.in_transaction or self.transaction_initiator != initiator:
            result = COMMIT_FAIL_NOT_IN_STAGE
        elif enclave_id < self.next_enclave_ID:
            result = self.next_enclave_ID
        else:
            self.next_enclave_ID = enclave_id + 1
            vlan_tag = -1
            for i in range(0, 4097):
                if self.available_vlan_tags[i]:
                    vlan_tag = i
                    self.available_vlan_tags[i] = False
                    break
            if vlan_tag == -1:
                result = COMMIT_FAIL_NO_ENOUGH_VLAN
            else:
                self.commited_list[enclave_id] = enclave.Enclave(enclave_id, initiator, True, vlan_tag)
                result = COMMIT_SUCCESS
                self.save_enclave_to_database(enclave_id, vlan_tag)
        self.update_lock.release()
        return result

    def roll_back_commit(self, enclave_ID):
        self.update_lock.acquire()
        if enclave_ID in self.commited_list:
            assigned_vlan_tag = self.commited_list[enclave_ID].vlan_tag
            self.commited_list.pop(enclave_ID)
            self.available_vlan_tags[assigned_vlan_tag] = True
            self.delete_enclave_from_database(assigned_vlan_tag)
        self.update_lock.release()

    def peak_next_enclave_id(self):
        self.update_lock.acquire()
        next_enclave_id = self.next_enclave_ID
        self.update_lock.release()
        return next_enclave_id

    def get_commited_enclaves(self):
        print self.commited_list
        return str(len(self.commited_list)) + str(self.commited_list)
    # def get_seq(self):
    #     self.update_lock.acquire()
    #     next_seq = self.seq
    #     self.seq += 1
    #     self.update_lock.release()
    #     return next_seq

    # def purpose_enclave(self):
    #     self.update_lock.acquire()
    #     next_enclave_id = self.next_enclave_ID
    #     self.next_enclave_ID += 1
    #     next_seq = self.seq
    #     self.seq += 1
    #     new_enclave = enclave.Enclave(next_enclave_id, self.addr, next_seq)
    #     self.update_lock.release()
    #     return new_enclave

    # def bind_enclave_vpn(self, enclave_id, vpn_host):
    #     # TODO save back up to database
    #     if enclave_id not in self.commited_list:
    #         return ENCLAVE_ID_NOT_COMMITTED
    #
    #     enclave_obj = self.commited_list[enclave_id]
    #     # enclave_vpn_host = enclave_obj.vpn_host
    #     # if enclave_vpn_host is None:
    #     #     return ENCLAVE_HAS_NO_VPN_ASSIGNED
    #
    #     enclave_vlan_tag = enclave_obj.vlan_tag
    #     vpn_host_switch_port = vpn_host.switch_port
    #     # vpn_mac_addr = vpn_host.mac_addr
    #     enclave_obj.append_enclave_switch_port(vpn_host_switch_port)
    #
    #     # TODO: Deal with failure
    #     # give a vlan tag to packect coming from the port connected to the vpn
    #     self.bind_port_to_vlan(vpn_host_switch_port, enclave_vlan_tag)
    #     self.bind_vlan_to_ports(enclave_vlan_tag, enclave_obj.switch_ports)
    #
    #     # for subnet in reachable_subnets:
    #     #     enclave_obj.append_reachable_subnet(subnet)
    #     #     self.add_route_to_vpn(enclave_vlan_tag, subnet, vpn_host_switch_port, vpn_mac_addr)
    #
    #     return SUCCESS
    #
    # def add_port_to_enclave(self, switch_port, enclave_id):
    #     # TODO save back up to database
    #     if enclave_id not in self.commited_list:
    #         return ENCLAVE_ID_NOT_COMMITTED
    #
    #     enclave_obj = self.commited_list[enclave_id]
    #     enclave_vlan_tag = enclave_obj.vlan_tag
    #     enclave_obj.append_enclave_switch_port(switch_port)
    #
    #     # TODO: Deal with failure
    #     # give a vlan tag to packet coming from a port
    #     self.bind_port_to_vlan(switch_port, enclave_vlan_tag)
    #
    #     self.bind_vlan_to_ports(enclave_vlan_tag, enclave_obj.switch_ports)
    #     return SUCCESS

    @staticmethod
    def init_database():
        conn = sqlite3.connect('enclave_service.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS enclaves(enclave_id INTEGER, vlan_tag INTEGER);''')
        c.execute('''CREATE TABLE IF NOT EXISTS vpnServers(enclave_id INTEGER, public_addr TEXT, interal_addr TEXT, key_dir TEXT, switch_port Text, subnet TEXT, bridge_int TEXT, eth_broadcast_addr Text, client_ip_pool_start Text, client_ip_pool_end Text);''')
        c.execute('''CREATE TABLE IF NOT EXISTS vpnClients(enclave_id INTEGER, server_addr TEXT, interal_addr TEXT, key_dir TEXT, switch_port Text, subnet TEXT, bridge_int TEXT, eth_broadcast_addr Text);''')

        conn.commit()
        return conn

    def save_enclave_to_database(self, enclave_id, vlan_tag):
        c = self.db_conn.cursor()
        c.execute('''INSERT INTO enclaves (enclave_id, vlan_tag) VALUES (?, ?)''', (enclave_id, vlan_tag))
        self.db_conn.commit()

    def delete_enclave_from_database(self, enclave_id):
        c = self.db_conn.cursor()
        c.execute('''DELETE FROM enclaves WHERE enclave_id=? ''', (enclave_id,))
        self.db_conn.commit()

    def save_vpn_server_to_database(self, enclave_id, public_addr, interal_addr, key_dir, switch_port, subnet, bridge_int, eth_broadcast_addr, client_ip_pool_start, client_ip_pool_end):
        c = self.db_conn.cursor()
        c.execute('''INSERT INTO vpnServers (enclave_id, public_addr, interal_addr, key_dir, switch_port, subnet, bridge_int, eth_broadcast_addr, client_ip_pool_start, client_ip_pool_end) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (enclave_id, public_addr, interal_addr, key_dir, switch_port, subnet, bridge_int, eth_broadcast_addr, client_ip_pool_start, client_ip_pool_end))
        self.db_conn.commit()

    def save_vpn_client_to_database(self, enclave_id, server_addr, interal_addr, key_dir, switch_port, subnet, bridge_int, eth_broadcast_addr):
        c = self.db_conn.cursor()
        c.execute(
            '''INSERT INTO vpnClients (enclave_id, server_addr, interal_addr, key_dir, switch_port, subnet, bridge_int, eth_broadcast_addr) VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (enclave_id, server_addr, interal_addr, key_dir, switch_port, subnet, bridge_int, eth_broadcast_addr))
        self.db_conn.commit()

    def bind_port_to_vlan(self, port, vlan_tag, datapath_id):
        datapath = self.datapath_dic[datapath_id]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # TODO make some of those values configurable
        # give a vlan tag to packect coming from the port connected to the vpn
        match = parser.OFPMatch(in_port=port)
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag))]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(1)]
        mod = datapath.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1000, table_id=0,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        # TODO: Deal with failure
        datapath.send_msg(mod)
        print("sent vlan to port binding")

    def bind_vlan_to_ports_strip(self, vlan_tag, ports, datapath_id):
        datapath = self.datapath_dic[datapath_id]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(vlan_vid=(0x1000 | (vlan_tag | 0x1000)))

        # append all ports belong to a enclave to to outgoing ports also forward packet
        # to local (ovsbr0) so that the switch can act as a default gateway
        actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        for port in ports:
            actions.append(parser.OFPActionOutput(port))

        # TODO make some of those values configurable
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1000, table_id=1,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        # TODO: Deal with failure
        datapath.send_msg(mod)
        print("sent vlan binding")

    def bind_vlan_to_ports_no_strip(self, vlan_tag, ports, datapath_id):
        datapath = self.datapath_dic[datapath_id]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(vlan_vid=(0x1000 | (vlan_tag | 0x1000)))

        # append all ports belong to a enclave to to outgoing ports also forward packet
        # to local (ovsbr0) so that the switch can act as a default gateway
        actions = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        for port in ports:
            actions.append(parser.OFPActionOutput(port))

        # TODO make some of those values configurable
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1000, table_id=1,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        # TODO: Deal with failure
        datapath.send_msg(mod)
        print("sent vlan binding")

    # def add_route_to_vpn(self, vlan_tag, subnet, vpn_switch_port, vpn_mac_addr):
    #     ofproto = self.datapath.ofproto
    #     parser = self.datapath.ofproto_parser
    #
    #     # change destination mac addr to the mac addr of vpn host so that
    #     # the vpn host can forward it
    #     match = parser.OFPMatch(vlan_vid=(0x1000 | (vlan_tag | 0x1000)), eth_type=0x0800, ipv4_dst=subnet)
    #     actions = [parser.OFPActionPopVlan(), parser.OFPActionSetField(eth_dst=vpn_mac_addr), parser.OFPActionOutput(vpn_switch_port)]
    #
    #     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    #     mod = self.datapath.ofproto_parser.OFPFlowMod(
    #         datapath=self.datapath, match=match, cookie=0,
    #         command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
    #         priority=2000, table_id=1,
    #         flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
    #     # TODO: Deal with failure
    #     self.datapath.send_msg(mod)
    #     print("add vpn static route")

    def add_vlan_to_primary_switch(self, enclave_id):
        enclave_item = self.commited_list[enclave_id]
        vlan_tag = enclave_item.vlan_tag
        vpn_ports = []
        for vpn_host in enclave_item.vpn_host_list:
            vpn_ports.append(vpn_host.switch_port)

        group_id = vlan_tag + 10
        datapath = self.primary_datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        bucket_action_list = []
        # strip off vlan tag and forward to vpn hosts of the enclave
        for vpn_port in vpn_ports:
            bucket_action_list.append([parser.OFPActionPopVlan(), parser.OFPActionOutput(vpn_port)])
        # keep vlan tag and forward to switch connected
        for port in self.primary_switch_down_ports:
            bucket_action_list.append([parser.OFPActionOutput(port)])
        buckets = []
        for bucket_action in bucket_action_list:
            buckets.append(parser.OFPBucket(actions=bucket_action))

        group_command = ofproto.OFPGC_ADD
        # TODO: NOT SURE IF CHANGING OFPGC_ADD TO OFPGC_MODIFY IS NECESSARY
        if enclave_id in self.is_primary_switch_enclave_group_set:
            group_command = ofproto.OFPGC_MODIFY
        self.is_primary_switch_enclave_group_set[enclave_id] = True
        req = parser.OFPGroupMod(datapath, group_command,
                                 ofproto.OFPGT_ALL, group_id, buckets)
        datapath.send_msg(req)

        # match packets coming from down ports with the vlan tag and forward to the above group
        for port in self.primary_switch_down_ports:
            match = parser.OFPMatch(in_port=port, vlan_vid=(0x1000 | (vlan_tag | 0x1000)))
            actions = [parser.OFPActionGroup(group_id)]
            # TODO make some of those values configurable
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=1000,
                flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
            # TODO: Deal with failure
            datapath.send_msg(mod)

        # for packets coming in from the vpn host, add a vlan tag and forward to down ports
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag))]
        for port in self.primary_switch_down_ports:
            actions.append(parser.OFPActionOutput(port))
        for vpn_port in vpn_ports:
            match = parser.OFPMatch(in_port=vpn_port)
            # append all ports belong to a enclave to to outgoing ports also forward packet
            # to local (ovsbr0) so that the switch can act as a default gateway
            # TODO make some of those values configurable
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=1000,
                flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
            # TODO: Deal with failure
            datapath.send_msg(mod)

    def bind_slave_switch_port_to_vlan(self, datapath_id, enclave_id, port_num):
        enclave_item = self.commited_list[enclave_id]
        vlan_tag = enclave_item.vlan_tag

        switch = self.slave_switch_dic[datapath_id]
        datapath = switch.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if enclave_id not in switch.enclave_ports_dic:
            switch.enclave_ports_dic[enclave_id] = []
        switch.enclave_ports_dic[enclave_id].append(port_num)
        existing_ports = switch.enclave_ports_dic[enclave_id]
        upwards_port = switch.upwards_port

        # match packets coming from upwards with the vlan tag, strip off vlan tag and forward to hosts in the enclave
        match = parser.OFPMatch(in_port=upwards_port,  vlan_vid=(0x1000 | (vlan_tag | 0x1000)))
        # append all ports belong to a enclave to to outgoing ports also forward packet
        # to local (ovsbr0) so that the switch can act as a default gateway
        actions = [parser.OFPActionPopVlan(), parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
        for port in existing_ports:
            actions.append(parser.OFPActionOutput(port))
        # TODO make some of those values configurable
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1000,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        # TODO: Deal with failure
        datapath.send_msg(mod)

        # for packects from the ports in the enclave,
        # 1. add vlan tag to it then
        # a forward to loacl port in the same enclave without vlan tag
        # b forward to upwards port with vlan tag attached
        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | vlan_tag))]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(1)]
        for port in existing_ports:
            match = parser.OFPMatch(in_port=port)
            # append all ports belong to a enclave to to outgoing ports also forward packet
            # to local (ovsbr0) so that the switch can act as a default gateway
            # TODO make some of those values configurable
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=1000,
                flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
            # TODO: Deal with failure
            datapath.send_msg(mod)

        # prepare the group
        group_id = vlan_tag + 10
        bucket_action_list = []
        # strip off vlan tag and forward to vpn hosts of the enclave
        for port in existing_ports:
            bucket_action_list.append([parser.OFPActionPopVlan(), parser.OFPActionOutput(port)])
        # keep vlan tag and forward switch connected
        bucket_action_list.append([parser.OFPActionOutput(upwards_port)])
        buckets = []
        for bucket_action in bucket_action_list:
            buckets.append(parser.OFPBucket(actions=bucket_action))

        group_command = ofproto.OFPGC_ADD
        if enclave_id in switch.is_enclave_group_set:
            group_command = ofproto.OFPGC_MODIFY
        switch.is_enclave_group_set[enclave_id] = True
        req = parser.OFPGroupMod(datapath, group_command,
                                 ofproto.OFPGT_ALL, group_id, buckets)
        datapath.send_msg(req)

        # match vlan and sent to the group
        match = parser.OFPMatch(vlan_vid=(0x1000 | (vlan_tag | 0x1000)))
        actions = [parser.OFPActionGroup(group_id)]
        # TODO make some of those values configurable
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1000, table_id=1,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        # TODO: Deal with failure
        datapath.send_msg(mod)

        return SUCCESS

    def ban_downwards_ports(self, dpid):
        switch = self.slave_switch_dic[dpid]
        datapath = switch.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for port in switch.downwards_ports:
            match = parser.OFPMatch(in_port=port)
            # actions = [parser.OFPActionGroup(group_id)]
            # TODO make some of those values configurable
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=100,
                flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
            # TODO: Deal with failure
            datapath.send_msg(mod)

    def add_primary_switch_direct_rule(self, port_src, port_dst):
        datapath = self.primary_datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=port_src)
        actions = [parser.OFPActionOutput(port_dst)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1000, table_id=0,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        # TODO: Deal with failure
        datapath.send_msg(mod)
