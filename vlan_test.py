from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.set_port_forwarding = False

    def set_vlan(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=5)

        actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=10)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=65534,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        datapath.send_msg(mod)
        # print(mod)

        match = parser.OFPMatch(vlan_vid=10)
        # change the the dst_port of matched tcp packets to 22 and output to switch 1
        # actions = [parser.OFPActionVlanVid(10), parser.OFPActionOutput(5)]
        actions = [parser.OFPActionOutput(5), parser.OFPActionOutput(1), parser.OFPActionPopVlan()]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0, table_id=1,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=65534,
            flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
        datapath.send_msg(mod)
        # print(mod)

        # match = parser.OFPMatch(dl_vlan=10)
        # # change the the dst_port of matched tcp packets to 22 and output to switch 1
        # actions = [parser.OFPActionOutput(1), parser.OFPActionOutput(5)]
        # mod = datapath.ofproto_parser.OFPFlowMod(
        #     datapath=datapath, match=match, cookie=0,
        #     command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
        #     priority=65534,
        #     flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        # datapath.send_msg(mod)
        # print(mod)

        # match = parser.OFPMatch(in_port=3)
        # # change the the dst_port of matched tcp packets to 22 and output to switch 1
        # actions = [parser.OFPActionVlanVid(10)]
        # mod = datapath.ofproto_parser.OFPFlowMod(
        #     datapath=datapath, match=match, cookie=0,
        #     command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
        #     priority=65534,
        #     flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        # datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        print(ev.msg)
        self.set_vlan(datapath)

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

    # learning switch part
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
        print msg

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # # learn a mac address to avoid FLOOD next time.
        # self.mac_to_port[dpid][src] = msg.in_port
        #
        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]
        # else:
        #     out_port = ofproto.OFPP_FLOOD
        #
        # actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        #
        # # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     self.add_flow(datapath, msg.in_port, dst, src, actions)
        #
        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data
        #
        # out = datapath.ofproto_parser.OFPPacketOut(
        #     datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
        #     actions=actions, data=data)
        # datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)