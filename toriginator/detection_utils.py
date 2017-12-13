from scapy.all import *
from ja3 import get_ja3_hash

def to_guard(consensus, pkt):
    try:
        router = consensus.routers.get(pkt[IP].dst)
        if 'Guard' in router.flags:
            return True
    except:
        return False

def from_exit(consensus, pkt):
    try:
        router = consensus.routers.get(pkt[IP].src)
        if 'Exit' in router.flags:
            return True
    except:
        return False

def tor_fingerprint(fingerprints, pkt):
    f = get_ja3_hash(pkt)
    if f in fingerprints:
        return True
    else:
        return False