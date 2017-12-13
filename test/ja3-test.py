import sys
sys.path.append('/Users/owen/Documents/Fall2017/COMP116/comp116-osearls/finalproject/Toriginator')
import toriginator
from scapy.all import *

try:
    packets = rdpcap(sys.argv[1])
except:
    print('tordetect.py: error: failed to open pcap file')
    sys.exit(1)

for pkt in packets:
    fp = toriginator.get_ja3_hash(pkt)
    if fp is not None:
        print fp