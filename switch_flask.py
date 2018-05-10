from flask import Flask, request
import os as os
app = Flask(__name__)

serviceStarted = False

command = "ovs-vsctl set-controller ovsbr0"


@app.route("/")
def hello():
    return "switch flask node is running"


@app.route("/set_master_controller", methods=['POST'])
def set_master_controller():
    configs = request.get_json(silent=True)
    address = configs["address"]
    port = str(configs["port"])
    global command
    command += (" tcp:" + address + ":" + port)
    return "master controller recorded"


@app.route("/new_controller", methods=['POST'])
def new_controller():
    configs = request.get_json(silent=True)
    address = configs["address"]
    port = str(configs["port"])
    global command
    command += (" tcp:" + address + ":" + port)
    os.system(command)
    return "new controller set"
