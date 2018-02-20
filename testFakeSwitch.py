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

OFP_HEADER_PACK_STR = '!BBHI'
OFP_SWITCH_FEATURES_PACK_STR = '!QIB3xII'


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
        self.config_msg = ev.msg
        # tries to connect to 7891
        s = connectionTest.connect_to_ip('localhost', 7891)
        msg = self.helo_msg
        msg.serialize()
        # send hello
        s.send(msg.buf)
        hello_from_switch = s.recv(20)
        print hello_from_switch

        msg = ev.msg
        # print(msg)
        config_msg = pack(OFP_HEADER_PACK_STR, 0x1, 0x6, 32, msg.xid)
        config_msg += pack(OFP_SWITCH_FEATURES_PACK_STR, msg.datapath_id, msg.n_buffers, msg.n_tables,
                      msg.capabilities, msg.actions)
        s.send(config_msg)
        print(len(config_msg))

        size = 0
        while s.recv(8):
            size += 1

        print "config_handler"


    @set_ev_cls(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        self.helo_msg = ev.msg
        print ev.msg
        print "hello_handler"

