from flask import Flask
# Do not change the following two lines
app = Flask(__name__)
from app import routes


app.get_port_return = routes.get_port_offset

app.set_self_addr = routes.set_self_addr

app.append_vpn_hosts = routes.append_vpn_host_list

app.append_datapath = routes.append_datapath

app.get_new_guest_controller_request = routes.get_new_guest_controller_request
