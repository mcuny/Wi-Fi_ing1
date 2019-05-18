import socket
import time
import sys

def server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.settimeout(0.2)
    server.bind(('', 37020))

    m = b'Hello'

    while True:
        server.sendto(m, ('<broadcast>', 44444))
        print('Sent: ', m)
        time.sleep(0.1)

server()

