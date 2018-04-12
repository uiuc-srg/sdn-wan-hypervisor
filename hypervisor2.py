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


def flaskThread():
    app.run("0.0.0.0", port=5678, debug=False)


def startServiceVPNChannel():
    # os.system("sshpass -p 'zys' scp -o StrictHostKeyChecking=no hypervisorVPNServer1.sh root@10.0.2.10:~/")
    # os.system("sshpass -p 'zys' ssh -o StrictHostKeyChecking=no -t root@10.0.2.10 'sh /root/hypervisorVPNServer1.sh'")
    keyDir = "/home/yuen/Desktop/openvpenca/keys"
    keyName = "server2"
    subNet = "10.0.200.0"
    vpnserver = "10.0.1.11"
    privatenets = "10.0.2.0,10.0.1.11"
    vpnclients = "client1,10.0.200.5,10.0.0.0"
    StartVPN.init_switch_ip("10.0.2.1", 24)
    app.set_self_addr("10.0.2.1")
    StartVPN.startServiceVPNServer("10.0.2.10:5000", keyDir, keyName, subNet, vpnserver, privatenets, vpnclients)
    os.system("route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.2.10")
    os.system("route add -net 10.0.200.0 netmask 255.255.255.0 gw 10.0.2.10")




class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v12.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.set_port_forwarding = False
        app.debug = False
        startServiceVPNChannel()
        thread.start_new_thread(flaskThread, ())

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.config_msg = ev.msg
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
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
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
            self.add_flow(datapath, 65534, match, actions)
        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
