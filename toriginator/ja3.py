#!/usr/bin/env python

#####
# Author: Tommy Stallings (tommy.stallings@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see LICENSE.txt file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
#####

from hashlib import md5

import struct
import traceback
import dpkt
import binascii
import socket
import json

DEBUG = False
TLS_HANDSHAKE = 22

# Well...this is neat
# https://tools.ietf.org/html/draft-davidben-tls-grease-00
GREASE_table = {
    0x0a0a : True,
    0x1a1a : True,
    0x2a2a : True,
    0x3a3a : True,
    0x4a4a : True,
    0x5a5a : True,
    0x6a6a : True,
    0x7a7a : True,
    0x8a8a : True,
    0x9a9a : True,
    0xaaaa : True,
    0xbaba : True,
    0xcaca : True,
    0xdada : True,
    0xeaea : True,
    0xfafa : True
}

# Borrowed from dpkt.ssl - lightly modified
def parse_variable_array(buf, lenbytes):

    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    # first have to figure out how to parse length
    assert lenbytes <= 4  # pretty sure 4 is impossible, too
    size_format = _SIZE_FORMATS[lenbytes - 1]
    padding = b'\x00' if lenbytes == 3 else b''
    # read off the length
    size = struct.unpack(size_format, padding + buf[:lenbytes])[0]
    # read the actual data
    data = buf[lenbytes:lenbytes + size]
    # if len(data) != size: insufficient data
    return data, size + lenbytes


def _ntoh(b):
  if len(b) == 1:
    return b[0]
  elif len(b) == 2:
    return struct.unpack('!H', b)[0]
  elif len(b) == 4:
    return struct.unpack('!I', b)[0]
  else:
    raise ValueError('Invalid input buffer size for ntoh')


def convert_to_ja3_seg(data, element_width):
    """Converts a packed array of elements to a JA3 segment.

    Args:
      data: string containing the packed elements
      element_width: integer width (in bytes) of each element
    Raises:
      ValueError if len(data) is not a multiple of element_width.
    """
    int_vals = []
    data = bytearray(data)

    if len(data) % element_width:
      raise ValueError('Element list %d is not a multiple of %d'
                       % (len(data), element_width))

    for i in range(0, len(data), element_width):
      element = _ntoh(data[i:i+element_width])
      if not element in GREASE_table:
        int_vals.append(element)

    return "-".join(str(x) for x in int_vals)

def convert_ip(val):
        try:
            return socket.inet_ntop(socket.AF_INET, val)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, val)

def get_ja3_hash(pkt, any_port=True):
    buf = str(pkt)
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except:
        return None

    # print('pkt: %d' % (pkt_count))

    if not isinstance(eth.data, dpkt.ip.IP):
        return None

    ip = eth.data
    if not isinstance(ip.data, dpkt.tcp.TCP):
        return None

    tcp = ip.data

    if not (tcp.dport == 443 or tcp.sport == 443 or any_port):
        return None

    if len(tcp.data) <= 0:
        return None

    # we only care about handshakes for now...
    tls_handshake = bytearray(tcp.data)
    if tls_handshake[0] != TLS_HANDSHAKE:
        return None

    records = []
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
    except dpkt.ssl.SSL3Exception:
        return None
    except dpkt.dpkt.NeedData:
        return None

    if len(records) <= 0:
        return None

    for record in records:

        # TLS handshake only
        if record.type != TLS_HANDSHAKE:
            continue

        if len(record.data) == 0:
            continue

        # Client Hello only
        client_hello = bytearray(record.data)
        if client_hello[0] != 1:
            continue

        if DEBUG:
            print("Hello DATA: %s" % binascii.hexlify(record.data))

        try:
            handshake = dpkt.ssl.TLSHandshake(record.data)
        except dpkt.dpkt.NeedData:
            continue

        if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
            continue

        ch = handshake.data

        if DEBUG:
            print("Handshake DATA: %s" % binascii.hexlify(ch.data))

        buf, ptr = parse_variable_array(ch.data, 1)
        buf, ptr = parse_variable_array(ch.data[ptr:], 2)
        ja3 = ["%d" % ch.version]

        # Cipher Suites (16 bit values)
        ja3.append(convert_to_ja3_seg(buf, 2))

        if hasattr(ch, "extensions"):

            exts = []
            ec = ""
            ec_pf = ""

            for ext_val, ext_data in ch.extensions:

                if not GREASE_table.get(ext_val):
                    exts.append(ext_val)

                if ext_val == 0x0a:
                    a, b = parse_variable_array(ext_data, 2)
                    # Elliptic curve points (16 bit values)
                    ec = convert_to_ja3_seg(a, 2)
                elif ext_val == 0x0b:
                    a, b = parse_variable_array(ext_data, 1)
                    # Elliptic curve point formats (8 bit values)
                    ec_pf = convert_to_ja3_seg(a, 1)

            ja3.append("-".join([str(x) for x in exts]))
            ja3.append(ec)
            ja3.append(ec_pf)
        else:
            # No extensions, so no curves or points.
            ja3.extend(["", "", ""])

        ja3 = ",".join(ja3)
        ja_digest = md5(ja3.encode()).hexdigest()
        return ja_digest
        