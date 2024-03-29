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


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, \
    MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_2 as ofproto_v12
from app import app
import thread
import middle_man
import time


def flask_thread():
    print "flask thread begins running"
    app.run("0.0.0.0", port=5678, debug=False)


def middle_man_tread():
    while True:
        new_guest_controller_request = app.get_new_guest_controller_request()
        if new_guest_controller_request is not None:
            if not new_guest_controller_request.only_forwarding:
                thread.start_new_thread(middle_man.middle_man,
                                        (new_guest_controller_request.datapath, new_guest_controller_request.vlan_tag,
                                         new_guest_controller_request.local_address,
                                         new_guest_controller_request.local_port,
                                         new_guest_controller_request.guest_controller_addr,
                                         new_guest_controller_request.guest_controller_port))
            else:
                thread.start_new_thread(middle_man.forwarding_thread,
                                        (new_guest_controller_request.guest_controller_addr,
                                         new_guest_controller_request.guest_controller_port,
                                         new_guest_controller_request.local_address,
                                         new_guest_controller_request.local_port))
        else:
            print "no new controller request======="
            time.sleep(10)


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
        thread.start_new_thread(middle_man_tread, ())
        print "middle man background thread started"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print ev.msg.datapath_id
        app.append_datapath(ev.msg.datapath_id, datapath)

    @set_ev_cls(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        self.helo_msg = ev.msg

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
