import sys
import argparse
from scapy.all import *

import toriginator

def parse_args():
    parser = argparse.ArgumentParser(description="""A network sniffer that
                                     identifies Tor traffic.""")
    parser.add_argument('-i', action="store", dest="interface",
                        help="Network interface to sniff on", default="eth0")
    parser.add_argument('-r', action="store", dest="pcap",
                        help="A PCAP file to read", default=None)
    parser.add_argument('-c', action="store", dest="consensus",
                        help="A Tor consensus file", default=None)
    return parser.parse_args()

def proccess_packet(pkt):
    if t.is_originating(pkt):
        print('detected originating traffic to Tor')

def main():
    args = parse_args()
    global t
    t = toriginator.Toriginator(args.consensus)

    if args.pcap != None:
        try:
            packets = rdpcap(args.pcap)
        except:
            print('tordetect.py: error: failed to open pcap file')
            sys.exit(1)

        for pkt in packets:
            proccess_packet(pkt)

    else:
        try:
            packets = sniff(iface=args.interface, prn=proccess_packet)
        except:
            print('tordetect.py: error: failed to initialize sniffing on '
                  + args.interface)
            sys.exit(1)
            
if __name__ == "__main__": main()