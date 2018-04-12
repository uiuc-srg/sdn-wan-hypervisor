from threading import Lock
import time
import enclave

import sqlite3

STAGE_SUCCESS = 0
STAGE_FAIL_INTRANSACTION = -1
COMMIT_SUCCESS = 0
COMMIT_FAIL = -1
COMMIT_FAIL_NOT_IN_STAGE = -1
COMMIT_FAIL_NO_ENOUGH_VLAN = -2


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
        self.vpn_hosts = {}
        self.seq = 0
        self.addr = ""
        self.transaction_initiator = ""
        self.stage_begin_time = time.time()
        self.subnets = ""
        self.db_conn = self.init_database()

    def set_self_addr(self, addr):
        self.addr = addr

    # return a dict, {interal_addr, public_addr}
    def get_next_vpn_host(self):
        self.update_lock.acquire()
        next_host = {}
        for host, available in self.vpn_hosts.iteritems():
            if available:
                next_host = host
                self.vpn_hosts[host] = False
        self.update_lock.release()
        return next_host

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

    def init_database(self):
        conn = sqlite3.connect('enclave_service.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS enclaves(enclave_id INTEGER, vlan_tag INTEGER);''')
        c.execute('''CREATE TABLE IF NOT EXISTS vpnServers(public_addr TEXT, interal_addr TEXT, enclave_id INTEGER, key_dir TEXT, key_name Text, vpn_subnet TEXT, privatenets TEXT, vpnclients Text);''')
        c.execute('''CREATE TABLE IF NOT EXISTS vpnClients(public_addr TEXT, interal_addr TEXT, enclave_id INTEGER, keyDir TEXT, keyName Text, serverAddr TEXT, nextHop TEXT);''')

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

    def save_vpn_server_to_database(self, enclave_id, keyDir, keyName, subNet, vpnserver_addr, privatenets, vpnclients, vpn_server_interal_addr):
        c = self.db_conn.cursor()
        c.execute('''INSERT INTO vpnServers (public_addr, interal_addr, enclave_id, key_dir, key_name, vpn_subnet, privatenet, vpnclients) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (vpnserver_addr, vpn_server_interal_addr, enclave_id, keyDir, keyName, subNet, privatenets, vpnclients))
        self.db_conn.commit()

    def save_vpn_client_to_database(self, enclave_id, client_public, client_private, keyDir, keyName, vpnserver_addr, next_hop):
        c = self.db_conn.cursor()
        c.execute(
            '''INSERT INTO vpnServers (public_addr, interal_addr, enclave_id, keyDir, keyName, serverAddr, nextHop) VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (client_public, client_private, enclave_id, keyDir, keyName, vpnserver_addr, next_hop))
        self.db_conn.commit()
