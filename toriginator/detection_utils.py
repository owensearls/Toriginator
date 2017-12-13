from scapy.all import *

def to_guard(self, consensus, pkt):
    try:
        router = consensus.routers.get(pkt[IP].dst)
        if 'Guard' in router.flags:
            return True
    except:
        return False

def from_exit(self, pkt):
    try:
        router = consensus.routers.get(pkt[IP].src)
        if 'Exit' in router.flags:
            return True
    except:
        return False

def tor_certificates(self, pkt)
    return pkt.haslayer(SSL)