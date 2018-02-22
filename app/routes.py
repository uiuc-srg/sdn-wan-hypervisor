from app import app
from threading import Lock

port_offset_lock = Lock()
port_offset = 3


@app.route('/')
@app.route('/index')
def index():
    return "Hello, here is the sdn config api!"


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
