from scapy.all import *

def print_ja3_hashes(cap, any_port=False, print_json=False):

    def convert_ip(val):
        try:
            return socket.inet_ntop(socket.AF_INET, val)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, val)

    for ts, buf in cap:

        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        # print('pkt: %d' % (pkt_count))

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        tcp = ip.data

        if not (tcp.dport == 443 or tcp.sport == 443 or any_port):
            continue

        if len(tcp.data) <= 0:
            continue

        # we only care about handshakes for now...
        tls_handshake = bytearray(tcp.data)
        if tls_handshake[0] != TLS_HANDSHAKE:
            continue

        records = []
        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception:
            continue
        except dpkt.dpkt.NeedData:
            continue

        if len(records) <= 0:
            continue

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
            if print_json:
                record = {"src":convert_ip(ip.src), "dst":convert_ip(ip.dst), "spt":tcp.sport, "dpt":tcp.dport, "ja3":ja_digest}
                print json.dumps(record)
            else:
                print("[%s:%s] JA3: %s --> %s" % (
                    convert_ip(ip.dst),
                    tcp.dport,
                    ja3,
                    ja_digest
                ))