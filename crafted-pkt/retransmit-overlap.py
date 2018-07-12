#!/usr/bin/env python
import argparse

from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("-w", dest="output_file", required=True,
                    help="Output pcap file")
args = parser.parse_args()


pkttime = 0


def tcp(data=b'', datalen=0, seq=None, rexmit=False):
    assert len(data) == datalen
    global pkttime
    relseq = seq
    seq += 4096
    ip = IP(src='10.0.0.2', dst='10.0.0.1')
    pkt = ip/TCP(flags='A', sport=32323, dport=25, ack=1024, seq=seq)/data
    if rexmit:
        pkttime += .1
    else:
        pkttime += .01
    pkt.time = pkttime
    return pkt


pkts = [
    tcp(seq=0,      data=b'DATA\r\n', datalen=6),
    tcp(seq=6,      data=b'To: <root@example.com>\r\n\r\n', datalen=26),
    tcp(seq=32,     data=b'1:segment that is fully rexmit.\n', datalen=32),
    tcp(seq=32,     data=b'1:segment that is fully rexmit.\n'+b'2', datalen=33, rexmit=True),
    tcp(seq=64,     data=b'2:first char (2) part of rexmit\n', datalen=32, rexmit=True),
    tcp(seq=96,     data=b"3:line that isn't retransmitted\n", datalen=32),
    tcp(seq=128,    data=b"4:retransmission after this:XYZ\n", datalen=32),
    tcp(seq=160-4,  data=b"XYZ\n"+b"5:new part after retransmission\n", datalen=4+32, rexmit=True),
    tcp(seq=192,    data=b"6:FINAL LINE, NOT RETRANSMITTED\n", datalen=32),
    tcp(seq=224,    data=b'\r\n.\r\n', datalen=5),
]

wrpcap(args.output_file, pkts)
