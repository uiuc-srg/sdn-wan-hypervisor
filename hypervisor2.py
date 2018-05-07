# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, \
    MAIN_DISPATCHER
import connectionTest
from struct import *
# from ryu.ofproto import ofproto_v1_0 as ofproto_v1
from ryu.ofproto import ofproto_v1_2 as ofproto_v12

from ryu.ofproto import ofproto_common
from ryu.ofproto import ofproto_parser
# from ryu.ofproto import ofproto_v1_0_parser as ofproto_v1_parser
from ryu.ofproto import ofproto_v1_2_parser as ofproto_v12_parser

from app import app
import thread
from socket import error as socket_error
import errno
import os as os
import startVPN as StartVPN


def flask_thread():
    print "flask thread begins running"
    app.run("0.0.0.0", port=5678, debug=False)


def start_service_vpn_channel():
    # os.system("sshpass -p 'zys' scp -o StrictHostKeyChecking=no hypervisorVPNServer1.sh root@10.0.2.10:~/")
    # os.system("sshpass -p 'zys' ssh -o StrictHostKeyChecking=no -t root@10.0.2.10 'sh /root/hypervisorVPNServer1.sh'")
    # StartVPN.init_switch_ip("10.0.2.1", 24)
    # app.set_self_addr("10.0.2.13")

    # internal_addr, public_addr, privatenet, switch_port, mac_addr, bridge_int, key_dir,
    #                      eth_broadcast_addr, client_ip_pool_start, client_ip_pool_end, available

    app.append_vpn_hosts("10.0.0.16", "10.0.1.13", "10.0.0.0", 5, "00:00:00:aa:00:0e", "eth1",
                         "/home/yuen/Desktop/openvpenca/keys/", "10.0.0.255", "10.0.0.50",
                         "10.0.0.100", True)


    # node_addr, node_internal_ip, node_public_ip, ca_location, cert_location, key_location,
    #                          dh_location, client_ip_pool_start, client_ip_pool_stop, subnet_behind_server,
    #                          bridged_eth_interface, eth_broadcast_addr
    node_internal_ip = "10.0.0.17"
    node_public_ip = "10.0.1.11"
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
    StartVPN.start_service_vpn_server("10.0.0.17:5000", node_internal_ip, node_public_ip, ca_location, cert_location,
                                      key_location, dh_location, client_ip_pool_start, client_ip_pool_stop,
                                      subnet_behind_server, bridged_eth_interface, eth_broadcast_addr)
    # os.system("route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.2.10")
    # os.system("route add -net 10.0.200.0 netmask 255.255.255.0 gw 10.0.2.10")
    print "primary vpn channel built"


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v12.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        print "init service"
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.set_port_forwarding = False
        app.debug = False
        # start_service_vpn_channel()
        # TODO consider to move this function to other location
        thread.start_new_thread(flask_thread, ())

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.config_msg = ev.msg
        print ev.msg.datapath_id
        app.append_datapath(ev.msg.datapath_id, datapath)
        # tries to connect to 7891
        # thread.start_new_thread(fake_switch_thread, (datapath, self.helo_msg, ev.msg, self))

    @set_ev_cls(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        self.helo_msg = ev.msg
        print ev.msg
        print "hello_handler"

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']
        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            # construct action list.
        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 20, match, actions)
        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
