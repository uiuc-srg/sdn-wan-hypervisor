from threading import Lock


class Service:
    def __init__(self):
        self._info_lock = Lock()
        self.vpn_host_list = []
        self.institution_list = []
        self.next_vpn_host_idx = 0

    def set_vpn_host_list(self, vpn_list):
        self._info_lock.acquire()
        self.vpn_host_list = vpn_list
        self._info_lock.release()

    def set_institution_list(self, institution_list):
        self.institution_list = institution_list

    def get_next_vpn_host(self):
        self._info_lock.acquire()
        next_host = self.vpn_host_list[self.next_vpn_host_idx]
        self.next_vpn_host_idx += 1
        self._info_lock.release()
        return next_host
