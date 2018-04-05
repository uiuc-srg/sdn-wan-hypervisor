from app import app
from threading import Lock
import enclave

port_offset_lock = Lock()
port_offset = 3


@app.route('/')
@app.route('/index')
def index():
    return "Hello, here is the sdn config api!"


# TODO: TRIGER RULE CHANGING WHEN HITTED
@app.route('/port/<offset>', methods=['PUT'])
def define_port_incr(offset):
    port_offset_lock.acquire()
    global port_offset
    port_offset = int(offset)
    port_offset_lock.release()
    return "new port offset set"


def get_port_offset():
    port_offset_lock.acquire()
    offset = port_offset
    port_offset_lock.release()
    return offset


@app.route('/enclave/new', methods=['PUT'])
def create_new_enclave():
    new_enclave = enclave.Enclave()
    return new_enclave.enclave_id
