import socket


def connect_to_ip(ip_addr, tcp_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip_addr, tcp_port)
    s.connect(server_address)
    return s
