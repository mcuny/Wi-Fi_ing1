from scapy.all import *
import sys
from rc4 import generate_seed, rc4
from scapy.utils import hexstr

if len(sys.argv) < 3:
    print('Usage: python3 sniff_decypher.py [AP_NAME] [Sniff count]')
    exit(1)

'''
First step: start sniffing the beacon
and find information about it
'''
AP_NAME = bytes(sys.argv[1], encoding='utf-8')
beacons = []

def sniff_beacons(pkt):
    global beacons
    if Dot11Beacon in pkt:
        try:
            if pkt.info == AP_NAME:
                beacons.append(pkt)
        except Exception as e:
            print(e)

sniff(count=150, iface="wlan0mon", prn=sniff_beacons)
AP_INFO = {
    'name': AP_NAME,
    'mac': beacons[0].addr2,
    'full_beacon': beacons[0]
}

'''
Capture a frame
'''
client_data = []
def sniff_client(pkt):
    global AP_INFO
    #FIXME:
    #  find dataframes: hint take a look at WireShark

sniff(count=int(sys.argv[2]), iface='wlan0mon', prn=sniff_client)

for cd in client_data:
    #FIXME:
    # LVL0: Send the message back to the sender
    # LVL1: Modify the payload and send the message back to the sender

    sendp(cd, iface='wlan0mon', count=1000)
