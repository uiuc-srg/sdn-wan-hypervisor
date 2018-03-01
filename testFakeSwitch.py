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
from ryu.lib.packet import ether_types
from ryu.controller.handler import set_ev_handler
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER,\
    MAIN_DISPATCHER
import connectionTest
from struct import *
from ryu.ofproto import ofproto_v1_0 as ofproto_v1
from ryu.ofproto import ofproto_common
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_0_parser as ofproto_v1_parser
from app import app
import thread
import time
from socket import error as socket_error
import errno


def flaskThread():
    app.run("127.0.0.1", port=5678, debug=False)


def recv_loop(socket):
    buf = bytearray()
    min_read_len = remaining_read_len = ofproto_common.OFP_HEADER_SIZE

    while True:
        read_len = min_read_len
        if remaining_read_len > min_read_len:
            read_len = remaining_read_len
        ret = socket.recv(read_len)

        if len(ret) == 0:
            return

        buf += ret
        buf_len = len(buf)
        while buf_len >= min_read_len:
            (version, msg_type, msg_len, xid) = ofproto_parser.header(buf)
            print(version, msg_type, msg_len, xid)
            if (msg_len < min_read_len):
                # Someone isn't playing nicely; log it, and try something sane.
                msg_len = min_read_len
            if buf_len < msg_len:
                remaining_read_len = (msg_len - buf_len)
                break
            return buf


def fake_switch_thread(datapath, hello_msg, switch_config_msg, switch_obj):
    s = 0

    while True:
        try:
            s = connectionTest.connect_to_ip('localhost', 7891)
            break
        except socket_error as serr:
            if serr.errno == errno.ECONNREFUSED:
                continue

    switch_obj.socket = s
    # send hello
    hello_msg.serialize()
    s.send(hello_msg.buf)

    hello_from_switch = recv_loop(s)
    print(hello_from_switch)

    # config stage
    config_msg = pack(ofproto_v1.OFP_HEADER_PACK_STR, 0x1, 0x6, 32, switch_config_msg.xid)
    config_msg += pack(ofproto_v1.OFP_SWITCH_FEATURES_PACK_STR, switch_config_msg.datapath_id, switch_config_msg.n_buffers, switch_config_msg.n_tables,
                       switch_config_msg.capabilities, switch_config_msg.actions)
    s.send(config_msg)

    # A msg for the match action is
    # |header 8|match 40|flowMod 72|action [set port OFP_ACTION_TP_PORT_PACK_STR 8] [OFP_ACTION_OUTPUT_PACK_STR 8]|
    port_offset = app.get_port_return()
    print(port_offset)

    # TODO: LOOK INTO WHY SWITCH CONFIG MESSAGE IS RECEIVED TWICE SOMETIMES
    version, msg_type, msg_len, xid = 0, 0, 0, 0
    while msg_type != 14:
        buf = recv_loop(s)
        (version, msg_type, msg_len, xid) = ofproto_parser.header(buf)

    print("RECEIVED MSG TYPE", msg_type)
    mod = ofproto_v1_parser.OFPFlowMod.parser(datapath, version, msg_type, msg_len, xid, buf)
    print("flow tp dst:", mod.match.tp_dst)
    mod.match.tp_dst += port_offset
    print("flow new tp dst:", mod.match.tp_dst)
    datapath.send_msg(mod)

    buf2 = recv_loop(s)
    (version, msg_type, msg_len, xid) = ofproto_parser.header(buf2)
    mod2 = ofproto_v1_parser.OFPFlowMod.parser(datapath, version, msg_type, msg_len, xid, buf2)
    print("flow tp src:", mod2.actions[0].tp)
    mod2.actions[0].tp += port_offset
    print("flow new tp src:", mod2.actions[0].tp)
    datapath.send_msg(mod2)
    print(mod2)

    buf3 = recv_loop(s)
    (version, msg_type, msg_len, xid) = ofproto_parser.header(buf3)
    mod3 = ofproto_v1_parser.OFPFlowMod.parser(datapath, version, msg_type, msg_len, xid, buf3)
    print(mod3)


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.set_port_forwarding = False
        app.debug = False
        thread.start_new_thread(flaskThread, ())

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.config_msg = ev.msg
        # tries to connect to 7891
        thread.start_new_thread(fake_switch_thread, (datapath, self.helo_msg, ev.msg, self))

    @set_ev_cls(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        self.helo_msg = ev.msg
        print ev.msg
        print "hello_handler"

    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
