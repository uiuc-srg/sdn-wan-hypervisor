class Enclave:
    _next_vlan_id = 1
    _next_enclave_id = 1

    def __init__(self):
        self.enclave_id = Enclave.generate_new_enclave_id()
        self.vlan_id = Enclave.generate_new_vlan_id()

    def get_vlan_id(self):
        return self.vlan_id

    def get_enclave_id(self):
        return self.enclave_id

    def write_to_db(self):
        pass

    @classmethod
    def generate_new_vlan_id(cls):
        temp = cls._next_enclave_id
        cls._next_enclave_id += 1
        return temp

    @classmethod
    def generate_new_enclave_id(cls):
        temp = cls._next_enclave_id
        cls._next_enclave_id += 1
        return temp
