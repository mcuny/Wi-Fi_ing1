from scapy.all import *

packet = RadioTap()/Dot11(addr1='20:aa:4b:f3:7e:b0', addr2='00:c0:ca:1a:05:11', addr3='20:aa:4b:f3:7e:b0')/\
         Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)

pkt = sendp(packet, iface='wlan0mon', count=1000)
print(pkt)

packet = RadioTap()/Dot11(addr1='20:aa:4b:f3:7e:b0', addr2='00:c0:ca:1a:05:11', addr3='20:aa:4b:f3:7e:b0')/\
Dot11AssoReq(cap=0x1100, listen_interval=0x00a)/\
Dot11Elt(ID=0, info="Cisco33141")

pkt = sendp(packet, iface='wlan0mon', count=1000)

pkt1 = RadioTap()/Dot11(addr1=broadcast,
                       addr2=bssid,
                       addr3=bssid)\
                /Dot11Beacon(cap=0x0421)\
                /Dot11Elt(ID=0, info='Cisco33141')\
                /Dot11Elt(ID=1, info='\x82\x84\x8b\x96\x96\x0c\x12\x18\x24')\
                /Dot11Elt(ID=3, info='\x0a')\
                /Dot11Elt(ID=5, info='\x00\x01\x00\x00')
