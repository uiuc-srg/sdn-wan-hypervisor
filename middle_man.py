from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER,\
    MAIN_DISPATCHER
import make_connection
from struct import *
# from ryu.ofproto import ofproto_v1_0 as ofproto_v1
from ryu.ofproto import ofproto_v1_2 as ofproto_v12
# from ryu.ofproto import ofproto_v1_3 as ofproto_v13
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_2_parser as ofproto_v12_parser

from socket import error as socket_error
from ryu.ofproto import ofproto_common
import thread
import errno
import socket
import time


def recv_loop(recv_socket):
    buf = bytearray()
    min_read_len = remaining_read_len = ofproto_common.OFP_HEADER_SIZE

    while True:
        read_len = min_read_len
        if remaining_read_len > min_read_len:
            read_len = remaining_read_len
        ret = recv_socket.recv(read_len)

        if len(ret) == 0:
            return

        buf += ret
        buf_len = len(buf)
        while buf_len >= min_read_len:
            (version, msg_type, msg_len, xid) = ofproto_parser.header(buf)
            if msg_len < min_read_len:
                # Someone isn't playing nicely; log it, and try something sane.
                msg_len = min_read_len
            if buf_len < msg_len:
                remaining_read_len = (msg_len - buf_len)
                break
            return buf


def guest_to_switch(guest_socket, switch_socket, datapath, vlan_tag):
    while True:
        guest_packet = recv_loop(guest_socket)
        if guest_packet is None:
            continue
        (version, msg_type, msg_len, xid) = ofproto_parser.header(guest_packet)
        if msg_type == 14:
            print("RECEIVED MSG TYPE", msg_type)
            msg = ofproto_v12_parser.OFPFlowMod.parser(datapath, version, msg_type, msg_len, xid, guest_packet)
            ofproto = datapath.ofproto
            raw_match = {'vlan_vid': (0x1000 | (vlan_tag | 0x1000))}
            parser = datapath.ofproto_parser
            for (k, v) in msg.match._fields2:
                print k
                print v
                raw_match[k] = v
            print raw_match
            match = parser.OFPMatch(**raw_match)
            inst = msg.instructions
            inst.append(parser.OFPInstructionGotoTable(4))
            # TODO CHANGE priority
            mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath, match=match, cookie=0,
                    command=msg.command, idle_timeout=0, hard_timeout=0,
                    priority=501, table_id=3,
                    flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
            datapath.send_msg(mod)
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0,
                command=msg.command, idle_timeout=0, hard_timeout=0,
                priority=501, table_id=1,
                flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=inst)
            datapath.send_msg(mod)
        else:
            switch_socket.send(guest_packet)


def switch_to_guest(switch_socket, guest_socket):
    while True:
        switch_packet = recv_loop(switch_socket)
        (version, msg_type, msg_len, xid) = ofproto_parser.header(switch_packet)
        if msg_type == 10:
            continue
        if switch_packet is not None:
            guest_socket.send(switch_packet)


def middle_man(datapath, vlan_tag, local_address, local_port, guest_controller_addr, guest_controller_port):
    print "new middle man started"
    guest_socket = None
    while True:
        try:
            time.sleep(1)
            guest_socket = make_connection.connect_to_ip(guest_controller_addr, guest_controller_port)
            print "received guest controller connection"
            break
        except socket_error as serr:
            if serr.errno == errno.ECONNREFUSED:
                continue

    listen_socket = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM)

    listen_socket.bind((local_address, local_port))
    # become a server socket
    listen_socket.listen(1)

    switch_socket, addr = listen_socket.accept()
    print "received switch connection"
    thread.start_new_thread(switch_to_guest, (switch_socket, guest_socket))
    thread.start_new_thread(guest_to_switch, (guest_socket, switch_socket, datapath, vlan_tag))


def direct_remote_to_guest(remote_socket, guest_socket):
    while True:
        remote_packet = recv_loop(remote_socket)
        if remote_packet is not None:
            guest_socket.send(remote_packet)


def direct_guest_to_remote(guest_socket, remote_socket):
    while True:
        guest_packet = recv_loop(guest_socket)
        if guest_packet is not None:
            remote_socket.send(guest_packet)


def forwarding_thread(guest_controller_addr, guest_controller_port, local_address, local_port):
    guest_socket = None
    while True:
        try:
            time.sleep(1)
            guest_socket = make_connection.connect_to_ip(guest_controller_addr, guest_controller_port)
            print "received guest controller connection"
            break
        except socket_error as serr:
            if serr.errno == errno.ECONNREFUSED:
                continue

    listen_socket = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.bind((local_address, local_port))
    listen_socket.listen(1)
    remote_socket, addr = listen_socket.accept()

    thread.start_new_thread(direct_guest_to_remote, (guest_socket, remote_socket))
    thread.start_new_thread(direct_remote_to_guest, (remote_socket, guest_socket))
