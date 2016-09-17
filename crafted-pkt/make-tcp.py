#!/usr/bin/env python2
# Create a crafted TCP stream with errors
# Usage: make-tcp.py [output.pcap]

import sys
from scapy.all import *

pkts = []
def send(data, flags='A'):
    if pkts:
        last = pkts[-1][TCP]
        seqno = last.seq + len(last.payload)
    else:
        seqno = 100
    tcp = TCP(sport=32323, dport=9, flags=flags, seq=seqno)/data
    pkt = IP(dst='10.0.0.2',src='10.0.0.1') / tcp
    pkts.append(pkt)
    return pkt

# data for one side
lines = [
    'First\n',
    'Second\n',
    'Third\n',
    'Fourth\n',
    'Fifth\n',
    'Sixth\n',
    'Last\n'
]
for line in lines:
    send(line)
send('', flags='F')  # FIN

# Errorneous packets
numbers = [
    1,
    1,  # duplicate packet
    2,
    4,  # out-of-order (2)
    3,  # out-of-order (1)
    5,
    #6, # missing packet
    7,
    0, # FIN (last packet)
]

# normal packets
#numbers = range(1, len(pkts)+1)

pkts2 = [pkts[i-1] for i in numbers]

# Show packets and write to file
for pkt in pkts2:
    print(pkt.summary())
if len(sys.argv) > 1:
    wrpcap(sys.argv[1], pkts2)
