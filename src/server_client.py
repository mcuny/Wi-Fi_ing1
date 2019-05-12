import socket
import time
import sys

from joblib import Parallel, delayed

mom_computer_IP='192.168.1.129'
mom_computer_MAC='e2:9e:66:eb:81:09'

max_computer_IP='192.168.1.137'
max_computer_MAC='80:d2:1d:0d:a0:99'

AP_IP='192.168.1.1'
AP_MAC='20:aa:4b:f3:7e:b0'

server_port=3333
client_port=4444

local_IP = (([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0]
if local_IP == mom_computer_IP:
    local_MAC = mom_computer_MAC
    dest_IP = max_computer_IP
    dest_MAC = max_computer_MAC
else:
    local_MAC = max_computer_MAC
    dest_IP = mom_computer_IP
    dest_MAC = mom_computer_MAC

def server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.settimeout(0.2)
    server.bind(('', server_port))

    m = bytes('[%s][%s] Hello' % (local_IP, local_MAC), encoding='utf-8')

    while True:
        server.sendto(m, ('<broadcast>', client_port))
        print('Sent: ', m)
        time.sleep(1)

def client():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(('', client_port))

    while True:
        data, addr = client.recvfrom(1024)
        print('Received: %s' % data)

if sys.argv[1] == 'client':
    client()
else:
    server()

