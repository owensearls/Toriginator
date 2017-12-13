# Toriginator
A library and command line program to detect and analyze originating traffic to
Tor. This project was undertaken to support the final essay "Identifying
Originating Traffic to Anonymity Networks" for COMP116 at Tufts University.

## tordetect
This program analyzes internet traffic from either a network interface or
packet capture file for evidence of Tor usage. It can detect traffic en-route
from a client to the Tor network by either checking against a database of known
Tor entry nodes or through some simple TLS fingerprinting. It will also flag
traffic coming from known Tor exit nodes.

```
usage: tordetect.py [-h] [-i INTERFACE] [-r PCAP] [-c CONSENSUS]
                    [-f FINGERPRINTS]

A network sniffer that identifies Tor traffic.

optional arguments:
  -h, --help       show this help message and exit
  -i INTERFACE     Network interface to sniff on
  -r PCAP          A PCAP file to read
  -c CONSENSUS     A Tor consensus file
  -f FINGERPRINTS  A list of JA3 fingerprints
```

## toriginator
The toriginator library includes methods to detect the different type of Tor
traffic supported by tordetect. It also exposes the underlying methods used to
collect the database of Tor servers and to fingerprint TLS packets.

## Attribution
This program takes inspiration from the tor-parser program available at
https://github.com/dgoulet/tor-parser for some of it's consensus processing
functions. It also uses a modified version of the JA3 Library located at
https://github.com/salesforce/ja3 to generate SSL fingerprints that can be
used to identify Tor clients.