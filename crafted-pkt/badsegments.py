#!/usr/bin/env python3
# Create a crafted TCP stream with overlapping and retransmitted segments
# Usage: badsegments.py [output.pcap]

import sys
from scapy.all import *


def make_tcp(server=None, flags=None, data=b'', datalen=0, **kwargs):
    assert type(server) == bool
    assert len(data) == datalen
    if not flags:
        flags = 'A'
    kwargs['seq' if server else 'ack'] += 0x44332211
    kwargs['ack' if server else 'seq'] += 0x88776655
    if 'A' not in flags:
        kwargs['ack'] = 0
    if server:
        tcp = TCP(flags=flags, sport=80, dport=32323, **kwargs)
        tcpip = IP(dst='10.0.0.1', src='10.0.0.2') / tcp
    else:
        tcp = TCP(flags=flags, sport=32323, dport=80, **kwargs)
        tcpip = IP(dst='10.0.0.2', src='10.0.0.1') / tcp
    return tcpip / data

s = lambda **kwargs: make_tcp(server=True, **kwargs)
c = lambda **kwargs: make_tcp(server=False, **kwargs)

pkts = []
# Cases:
# 1. two sequential segments
# 2. out-of-order (swapped two sequential segments)
# 3. Bad overlap (second overlap with different data should be ignored)
# 4. Ignore bad retransmitted data, but extend with remaining data.
# 5. Check handling of overlapping data while fragments are incomplete
#    (out-of-order - cannot add fragments to stream)
# 6. lost but acked segments
# 7. lost 3/5 fragments, but acked
# TODO lost and not acked (currently truncated, is that OK?)

bad = len(sys.argv) <= 2 or sys.argv[2] != 'ok'

pkts += [
c(seq=0,    ack=0,  flags='S'),
s(seq=0,    ack=1,  flags='SA'),
c(seq=1,    ack=1,  flags='A'),

# 1. two sequential segments
c(seq=1,    ack=1,  data=b'GET / HTTP/1.1\r\n', datalen=16),
c(seq=17,   ack=1,  data=b'Host:localhost\r\n', datalen=16),
]

pkts += [
# 2. out-of-order (swapped two sequential segments)
c(seq=33,   ack=1,  data=b'X-Swapped: 1st\r\n', datalen=16),
c(seq=49,   ack=1,  data=b'X-Swapped: 2nd\r\n', datalen=16),
][::-1 if bad else 1]
pkts += [
s(seq=1,    ack=65),
]

pkts += [
# 3. Bad overlap (second overlap with different data should be ignored)
c(seq=65,   ack=1,  data=b'X-Overlap-Packet', datalen=16),
c(seq=65,   ack=1,  data=b'X-Overlap-IGNORE', datalen=16),
][:2 if bad else 1]

pkts += [
# 4. Ignore bad retransmitted data, but extend with remaining data.
c(seq=65,   ack=1,  data=b'X-BADOVERLAPHEAD: extra data--\r\n', datalen=32),
s(seq=1,    ack=97),
]

# 5. Check handling of overlapping data while fragments are incomplete
#    (out-of-order - cannot add fragments to stream)
pkts += [
c(seq=113,  ack=1,  data=b'his is delayed\r\n', datalen=16),
c(seq=161,  ack=1,  data=b'X-OoO-Overlap3:e', datalen=16),
c(seq=161,  ack=1,  data=b'X-OoO-Overlap3:extend fragment\r\n', datalen=32),
c(seq=97,   ack=1,  data=b'X-OoO-Overlap: t', datalen=16),
c(seq=129,  ack=1,  data=b'X-OoO-Overlap2: second delayed\r\n', datalen=32),
]

pkts += [
# 6. lost but acked segments
c(seq=193,  ack=1,  data=b'Cookie: value=1234567890abcdef\r\n', datalen=32),
c(seq=225,  ack=1,  data=b'X-Missing-But-Acked-Previous:1\r\n', datalen=32),
s(seq=1,    ack=257),
][1 if bad else 0:]

pkts += [
# 7. lost 3/5 fragments, but acked
c(seq=257,  ack=1,  data=b'X-IGNORED-ANYWAY: wjedgfjrsfdg\r\n', datalen=32),
c(seq=287,  ack=1,  data=b'\r', datalen=1),
c(seq=273,  ack=1,  data=b':', datalen=1),
c(seq=289,  ack=1,  data=b'X-Missing-3-Out-Of-5-But-ACK:Y\r\n', datalen=32),
s(seq=1,    ack=321),
][1 if bad else 0:]

pkts += [
c(seq=321,   ack=1,  data=b'\r\n', datalen=2),
s(seq=1,    ack=323),
]

# Show packets and write to file
for i, pkt in enumerate(pkts):
    pkt.time = i * 0.000001
    print(pkt.summary())
if len(sys.argv) > 1:
    wrpcap(sys.argv[1], pkts)
