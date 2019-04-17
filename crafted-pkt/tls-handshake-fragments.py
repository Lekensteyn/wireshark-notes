#!/usr/bin/env python3
import argparse
import random

from scapy.all import *

# msg_type: 1 (Client Hello)
# length: 47
#   client_version: 1.2
#   random: 32 bytes
#   session_id: empty
#   cipher_suite[1]: 0x002F (TLS_RSA_WITH_AES_128_CBC_SHA)
#   compression_method[1]: null
#   extensions[1]: 0xAAAA (GREASE) with two values (will be used as identifier)
clientHelloMsg = bytes([
    0x01,
    0x00, 0x00, 0x31,
    0x03, 0x03,
]) + 32 * b'3' + bytes([
    0x00,
    0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
    0x00, 0x06, 0xaa, 0xaa, 0x00, 0x02,
    0x00, 0x00
])
assert len(clientHelloMsg) == 53
clientHelloMsgBase = clientHelloMsg[:-2]

def CH(num : int):
    '''Returns a Client Hello message with some identifier.'''
    return clientHelloMsgBase + num.to_bytes(2, 'big')

def TLSRecord(data):
    # Handshake (22), TLSv1.0
    return b'\x16\x03\x01' + len(data).to_bytes(2, 'big') + data

parser = argparse.ArgumentParser()
parser.add_argument('--seed', type=int)
parser.add_argument('--count', type=int, default=256, help='Streams count')
parser.add_argument('output_file')
args = parser.parse_args()

if args.seed is not None:
    random.seed(args.seed)

# Pick a number of messages per stream such that at least the case is triggered
# where a record contains the end of a message, a full message and the start of
# another message. A lot more than three per record will likely not be useful
# since it does not trigger reassembly.
hsPerStream = 10
maxRecordSize = len(clientHelloMsg) * 4

# Fragment handshake message over TLS records,
# fragment TLS records over TCP segments.
packets = []
for i in range(args.count):
    hs = b''.join(CH(hsPerStream * i + j + 1) for j in range(hsPerStream))
    seq = 0x1000
    while hs:
        # Does not matter that n > maxRecordSize, it is capped anyway.
        n = random.randint(1, maxRecordSize)
        recordData, hs = hs[:n], hs[n:]
        seg = TLSRecord(recordData)
        pkt = IP()/TCP(flags='A', seq=seq, sport=0xc000 + i, dport=443)/seg
        packets.append(pkt)
        seq += len(seg)

wrpcap(args.output_file, packets)

r"""
Test:

    tshark -r hs-frag.pcapng -Tfields -Y tls.handshake.extension.data -e tls.handshake.extension.data | tr , '\n'

Expected result: for a given 'count' streams, expect hexadecimal numbers 0001 up
to and including 10*count. E.g. for --count=10 the output should match:

    printf '%004x\n' {1..100}
"""
