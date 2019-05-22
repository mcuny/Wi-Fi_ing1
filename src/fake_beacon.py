from scapy.all import *
import sys

broadcast = 'ff:ff:ff:ff:ff:ff'
client = '00:c0:ca:1a:05:12'
bssid = '20:AA:4B:F3:7E:B0'

pkt1 = RadioTap()/Dot11(addr1=broadcast,
                       addr2=bssid,
                       addr3=bssid)\
                /Dot11Beacon(cap=0x0421)\
                /Dot11Elt(ID=0, info='Cisco33141')\
                /Dot11Elt(ID=1, info='\x82\x84\x8b\x96\x96\x0c\x12\x18\x24')\
                /Dot11Elt(ID=3, info='\x0a')\
                /Dot11Elt(ID=5, info='\x00\x01\x00\x00')

sendp(pkt, iface='wlan0mon', count=10000, inter=.01)
