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
