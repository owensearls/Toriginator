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
    parser.add_argument('-f', action="store", dest="fingerprints",
                        help="A list of JA3 fingerprints",
                        default='test/torfingerprint.txt')
    return parser.parse_args()

issued = set()
def print_alert(type, ip):
    global issued

    alerts = {'guard': 'Detected traffic to Tor router from {ip}.',
              'exit': 'Detected traffic from Tor exit node with IP {ip}.',
              'fp': 'Detected traffic matching Tor fingerprint from {ip}.'}

    alert = alerts.get(type)
    if alert is None:
        return

    if alert not in issued:
        issued.add(alert)
        print(alert.format(ip=ip))

def proccess_packet(consensus, fingerprints, pkt):
    if toriginator.to_guard(consensus, pkt):
        print_alert('guard', pkt[IP].src)
    if toriginator.from_exit(consensus, pkt):
        print_alert('exit', pkt[IP].dst)
    if toriginator.tor_fingerprint(fingerprints, pkt):
        print_alert('fp', pkt[IP].src)

def main():
    args = parse_args()
    fingerprints = set(open(args.fingerprints).readlines())
    consensus = toriginator.Consensus(args.consensus)

    if args.pcap != None:
        try:
            packets = rdpcap(args.pcap)
        except:
            print('tordetect.py: error: failed to open pcap file')
            sys.exit(1)

        for pkt in packets:
            proccess_packet(consensus, fingerprints, pkt)

    else:
        try:
            packets = sniff(iface=args.interface,
                            prn=lambda p: proccess_packet(consensus,
                                                          fingerprints,
                                                          p))
        except:
            print('tordetect.py: error: failed to initialize sniffing on '
                  + args.interface)
            sys.exit(1)
            
if __name__ == "__main__": main()