from flask import Flask

app = Flask(__name__)

from app import routes

app.get_port_return = routes.get_port_offset

