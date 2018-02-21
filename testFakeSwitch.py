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


# OFP_HEADER_PACK_STR = '!BBHI'
# OFP_SWITCH_FEATURES_PACK_STR = '!QIB3xII'


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.set_port_forwarding = False
        # self.helo_msg = ''
        # self.config_msg = ''

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.config_msg = ev.msg
        # tries to connect to 7891
        s = connectionTest.connect_to_ip('localhost', 7891)
        self.socket = s
        msg = self.helo_msg
        msg.serialize()
        # send hello
        s.send(msg.buf)
        hello_from_switch = s.recv(20)
        # print hello_from_switch

        # config stage
        msg = ev.msg
        config_msg = pack(ofproto_v1.OFP_HEADER_PACK_STR, 0x1, 0x6, 32, msg.xid)
        config_msg += pack(ofproto_v1.OFP_SWITCH_FEATURES_PACK_STR, msg.datapath_id, msg.n_buffers, msg.n_tables,
                      msg.capabilities, msg.actions)
        s.send(config_msg)

        # A msg for the match action is
        # |header 8|match 40|flowMod 72|action [set port OFP_ACTION_TP_PORT_PACK_STR 8] [OFP_ACTION_OUTPUT_PACK_STR 8]|

        buf = self._recv_loop()
        (version, msg_type, msg_len, xid) = ofproto_parser.header(buf)
        mod = ofproto_v1_parser.OFPFlowMod.parser(datapath, version, msg_type, msg_len, xid, buf)
        print("flow tp dst:", mod.match.tp_dst)
        mod.match.tp_dst += 2
        print("flow new tp dst:", mod.match.tp_dst)
        datapath.send_msg(mod)


        # (wildcards, in_port, dl_src,
        #  dl_dst, dl_vlan, dl_vlan_pcp,
        #  dl_type, nw_tos, nw_proto,
        #  nw_src, nw_dst, tp_src, tp_dst) = unpack_from(ofproto_v1.OFP_MATCH_PACK_STR,
        #                                                buf, ofproto_v1.OFP_HEADER_SIZE)
        #
        # match = ofproto_v1_parser.OFPMatch.parse(buf, ofproto_v1.OFP_HEADER_SIZE)
        # print(in_port, dl_type, nw_proto, nw_dst, nw_src, tp_dst)
        #
        # (cookie, command,
        # idle_timeout, hard_timeout,
        # priority, buffer_id, out_port,
        # flags) = unpack_from(ofproto_v1.OFP_FLOW_MOD_PACK_STR0,
        #                                                buf, ofproto_v1.OFP_HEADER_SIZE + ofproto_v1.OFP_MATCH_SIZE)

        buf2 = self._recv_loop()
        (version, msg_type, msg_len, xid) = ofproto_parser.header(buf2)
        mod2 = ofproto_v1_parser.OFPFlowMod.parser(datapath, version, msg_type, msg_len, xid, buf2)
        print("flow tp src:", mod2.actions[0].tp)
        mod2.actions[0].tp += 2
        print("flow new tp src:", mod2.actions[0].tp)
        datapath.send_msg(mod2)
        print(mod2)


        buf3 = self._recv_loop()
        (version, msg_type, msg_len, xid) = ofproto_parser.header(buf3)
        mod3 = ofproto_v1_parser.OFPFlowMod.parser(datapath, version, msg_type, msg_len, xid, buf3)
        print(mod3)


        # (wildcards, in_port, dl_src,
        # dl_dst, dl_vlan, dl_vlan_pcp,
        # dl_type, nw_tos, nw_proto,
        # nw_src, nw_dst, tp_src, tp_dst) = unpack_from(ofproto_v1.OFP_MATCH_PACK_STR,
        #                      buf, ofproto_v1.OFP_HEADER_SIZE)

        # print(in_port, dl_type, nw_proto, str(nw_dst), str(nw_src), tp_dst)


        # ev = self._recv_loop()
        #
        # msg_buf = ev.msg.buf
        # match = unpack_from(ofproto_v1.OFP_MATCH_PACK_STR,
        #                     msg_buf, ofproto_v1.OFP_HEADER_SIZE)
        # print(match)
        # print(ev.msg.OFPMatch)


        print "config_handler"


    @set_ev_cls(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        self.helo_msg = ev.msg
        print ev.msg
        print "hello_handler"

    def _recv_loop(self):
        buf = bytearray()
        min_read_len = remaining_read_len = ofproto_common.OFP_HEADER_SIZE

        while True:
            read_len = min_read_len
            if remaining_read_len > min_read_len:
                read_len = remaining_read_len
            ret = self.socket.recv(read_len)

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
                # msg = ofproto_parser.msg(
                #     self, version, msg_type, msg_len, xid, buf[:msg_len])
                # # LOG.debug('queue msg %s cls %s', msg, msg.__class__)
                # if msg:
                #     ev = ofp_event.ofp_msg_to_ev(msg)
                #     # self.ofp_brick.send_event_to_observers(ev, self.state)
                #     # return ev
                #
                #
                # buf = buf[msg_len:]
                # buf_len = len(buf)
                # remaining_read_len = min_read_len

                # We need to schedule other greenlets. Otherwise, ryu
                # can't accept new switches or handle the existing
                # switches. The limit is arbitrary. We need the better
                # approach in the future.


                # learning switch part

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