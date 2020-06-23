#!/usr/bin/env python3
# Reorder a pcap file with a single TCP stream. Convert with
# 'tshark -r input.pcapng -w output.pcap -F pcap' if scapy crashes with
# "struct.error: 'I' format requires 0 <= number <= 4294967295" in
# _write_packet.

import argparse
import logging
import time

from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument('--linktype', type=int, default=1,
                    help='DLT (0 for Null/Loopback, 1 for Ethernet)')
parser.add_argument('infile')
parser.add_argument('outfile')


def main():
    args = parser.parse_args()
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)

    t1 = time.monotonic()
    packets = rdpcap(args.infile)
    t2 = time.monotonic()
    logging.info('Capture loaded in %.3f seconds', t2 - t1)

    # Assume a single stream
    clt = packets[0][TCP]
    svr = packets[1][TCP]
    assert clt.flags.S and not clt.flags.A
    assert svr.flags.S and svr.flags.A
    assert clt.sport == svr.dport
    assert clt.dport == svr.sport
    assert clt.dport != clt.sport

    def seq_key(p):
        t = p[TCP]
        if t.sport == svr.sport:
            return t.seq - svr.seq
        elif t.dport == svr.sport:
            return t.ack - svr.seq
        else:
            raise RuntimeError(f'Unexpected {t}')
    packets.sort(key=seq_key)

    t1 = time.monotonic()
    wrpcap(args.outfile, packets, linktype=args.linktype)
    t2 = time.monotonic()
    logging.info('Capture written in %.3f seconds', t2 - t1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
