#!/usr/bin/env python
# Reads a pcap and shows sequence issues (retransmissions, out-of-order, etc).
import argparse
import sys

from scapy.all import *


def identify(pkt):
    ip = pkt[IP]
    tcp = ip[TCP]
    addr = '%s-%d-%s-%d' % (ip.src, tcp.sport, ip.dst, tcp.dport)
    return addr.replace(':', '_')


parser = argparse.ArgumentParser()
parser.add_argument("-s", dest="stream", type=int, help="Select stream number")
parser.add_argument("-r", dest="input_file", required=True, help="Input pcap")
args = parser.parse_args()

# map (ip.src)-(tcp.srcport)-(ip.dst)-(tcp.dstport) -> [<packet>..]
tcp_packets = {}
stream_ids = []

# Group packets per TCP/IP tuple
pkts = rdpcap(args.input_file)
for pktno, pkt in enumerate(pkts, 1):
    if not TCP in pkt:
        continue
    tcp = pkt[TCP]
    if type(tcp.payload) != Raw:
        continue
    payload = tcp.payload.load
    if not payload:
        continue
    address = identify(pkt)
    if address not in stream_ids:
        stream_ids.append(address)
    tcp_packets.setdefault(address, []).append((pktno, pkt))

# Select packet
if not tcp_packets:
    sys.exit("No TCP data packets found")
elif args.stream is not None:
    try:
        stream = stream_ids[args.stream]
        mypackets = tcp_packets[stream]
    except KeyError:
        sys.exit("Requested stream %d was not found", args.stream)
elif len(tcp_packets) == 1:
    mypackets = next(iter(tcp_packets.values()))
else:
    print("Too many addresses, select one of them:")
    print("%4s %-42s %7s %s" % ("Strm", "Addr", "Count", "Bytes"))
    for stream, address in enumerate(stream_ids):
        mypkts = tcp_packets[address]
        pkts_count = len(mypkts)
        pkts_bytes = sum(len(mypkt[TCP].payload.load)
                         for pktno, mypkt in mypkts)
        print("%3d %-43s %7d %d" % (stream, address, pkts_count, pkts_bytes))
    sys.exit(1)


def relative_tcp_seq_no(firstseq):
    def seqno_func(pkt):
        tcp = pkt[TCP]
        seq = tcp.seq - firstseq
        if seq < 0:
            seq += 2**32
        # Sort larger (retransmitted) segments first such that smaller one that
        # are embedded in that one are ignored.
        return (seq, -len(tcp.payload.load))
    return seqno_func


# Fix broken interpretation due to a Scapy bug
# https://github.com/secdev/scapy/pull/1512
for i, (pktno, pkt) in enumerate(mypackets):
    if pkt[IP].len == 0:
        pkt.load += pkt[Padding].load
        del pkt[Padding]
        pkt[IP].len = None
        mypackets[i] = Ether(bytes(pkt))
        assert mypackets[i][IP].len != 0


class SegmentInfo(object):
    def __init__(self, seq, nextseq):
        self.seq = seq
        self.nextseq = nextseq
        self.seglen = nextseq - seq


class Stream(object):
    def __init__(self):
        self.segments = []
        self.unhandled_segments = []
        self.iseq = None
        self.nextseq = None
        self.errors = {}

    def add_segment(self, pkt):
        self.segments.append(pkt)
        assert pkt.seq <= self.nextseq
        assert type(pkt[TCP].payload == Raw)
        self.nextseq = pkt.seq + len(pkt[TCP].payload.load)

    def add(self, pktno, pkt):
        assert type(pkt[TCP].payload == Raw)
        segdata = pkt[TCP].payload.load
        seglen = len(segdata)
        seq = pkt.seq
        nextseq = pkt.seq + seglen

        is_initial = self.nextseq is None
        # Set initial seqno
        if self.iseq is None:
            self.iseq = pkt.seq
            self.nextseq = nextseq

        # Ignore segments with no data
        if seglen == 0:
            return

        # Handle normal case
        if is_initial:
            # Handle initial packet
            self.add_segment(pkt)
            return
        elif seq == self.nextseq:
            # Handle sequential packets
            self.add_segment(pkt)
            self.process_unhandled()
            return

        # Handle error cases
        if nextseq <= self.nextseq:
            # Ignore full retransmissions
            assert seq < self.nextseq
            self.errors[pktno] = "Retransmission"
            # TODO check overlap conflicts for (seq, nextseq)
        elif seq > self.nextseq:
            # Handle gap segment (possibly lost segment before or OoO)
            # (possible overlap with previous unhandled segments)
            self.errors[pktno] = "Out-of-Order (%d > %d)" % (
                seq - self.iseq, self.nextseq - self.iseq)
            # TODO check overlap conflicts for (seq, nextseq)
            overlap_error = self.has_overlap(seq, nextseq)
            if overlap_error == 1:
                self.errors[pktno] += " / Partial Retransmission"
            elif overlap_error == 2:
                self.errors[pktno] += " / Retransmission"
            if overlap_error != 2:
                # potential new data, so save it.
                self.add_unhandled(pktno, seq, nextseq, pkt)
        else:
            # Else partial overlap. Find out if it is retrans + extra data
            # (possible overlap with previous unhandled segments)
            # This could result in removing segments from "unhandled_segments"
            # and must add to "segments".
            assert seq < self.nextseq
            # TODO check overlap conflicts for (seq, self.nextseq)
            overlap_error = self.has_overlap(self.nextseq, nextseq)
            if overlap_error != 2:
                self.errors[pktno] = "Partial Retransmission"
                self.add_unhandled(pktno, seq, nextseq, pkt)
                self.process_unhandled()
            else:
                self.errors[pktno] = "Retransmission"

    def has_overlap(self, seq, nextseq):
        """
        Returns 0 if there is no overlap.
        Returns 1 if there is a partial overlap (partial retransmission).
        Returns 2 if there is a full overlap (retransmission).
        """
        assert seq < nextseq
        newseq = seq
        for pktno, pkt in self.unhandled_segments:
            if pkt.seq > nextseq:
                # Note: could have continued searching in order to detect
                # conflicting overlaps.
                break
            pkt_nextseq = pkt.seq + len(pkt[TCP].payload.load)
            newseq = max(newseq, pkt_nextseq)
            if newseq >= nextseq:
                # Full overlap
                return 2
        if newseq > seq:
            # partial overlap
            return 1
        else:
            # no overlap
            return 0

    def process_unhandled(self):
        """Try to reassemble segments."""
        errors = []
        remove = 0
        for pktno, pkt in self.unhandled_segments:
            if pkt.seq > self.nextseq:
                break

            nextseq = pkt.seq + len(pkt[TCP].load)
            if pkt.seq == self.nextseq:
                # perfect adjacent
                self.add_segment(pkt)
            else:
                assert pkt.seq < self.nextseq
                overlap = self.nextseq - pkt.seq
                # partial overlap
                # pkt.load[:overlap]
                errors.append("Overlap: %d - %d (%d bytes)" % (pkt.seq,
                                                               self.nextseq, overlap))
                # XXX append partial? Or leave up to reassembly API?
                self.add_segment(pkt)
            remove += 1
        self.unhandled_segments = self.unhandled_segments[remove:]
        if errors:
            error = ", ".join(errors)
            if pktno in self.errors:
                self.errors[pktno] += " / " + error
            else:
                self.errors[pktno] = error

    def add_unhandled(self, pktno, seq, nextseq, pkt):
        """Remembers a segment for later use."""
        assert seq < nextseq

        # Ensure that for each segment x, y:
        # x.seq < y.seq or (x.seq == y.seq and x.nextseq <= y.nextseq)
        insertPos = 0
        for i, (pktno2, pkt2) in enumerate(self.unhandled_segments):
            if seq > pkt2.seq:
                break
            if seq == pkt2.seq and nextseq > pkt2.nextseq:
                break
            insertPos = i
        self.unhandled_segments.insert(insertPos, (pktno, pkt))


stream = Stream()
for pktno, pkt in mypackets:
    stream.add(pktno, pkt)
    print("%3d " % (pktno), end="")
    seglen = len(pkt[TCP].load)
    print("seq=%-5d nextseq=%-5d len=%-4d " %
          (pkt.seq - stream.iseq, pkt.seq + seglen - stream.iseq, seglen), end="")
    if pktno in stream.errors:
        print(stream.errors[pktno])
    else:
        print("OK")
