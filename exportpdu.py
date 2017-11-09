#!/usr/bin/env python
import argparse
import struct
# So slow... let's import what we need.
#from scapy.all import *
from scapy.fields import StrField
from scapy.packet import Packet
from scapy.utils import wrpcap

# From epan/exported_pdu.h
EXP_PDU_TAG_END_OF_OPT                      = 0
EXP_PDU_TAG_OPTIONS_LENGTH                  = 10
EXP_PDU_TAG_LINKTYPE                        = 11
EXP_PDU_TAG_PROTO_NAME                      = 12
EXP_PDU_TAG_HEUR_PROTO_NAME                 = 13
EXP_PDU_TAG_DISSECTOR_TABLE_NAME            = 14
EXP_PDU_TAG_IPV4_SRC                        = 20
EXP_PDU_TAG_IPV4_DST                        = 21
EXP_PDU_TAG_IPV6_SRC                        = 22
EXP_PDU_TAG_IPV6_DST                        = 23
EXP_PDU_TAG_PORT_TYPE                       = 24
EXP_PDU_TAG_SRC_PORT                        = 25
EXP_PDU_TAG_DST_PORT                        = 26
EXP_PDU_TAG_SS7_OPC                         = 28
EXP_PDU_TAG_SS7_DPC                         = 29
EXP_PDU_TAG_ORIG_FNO                        = 30
EXP_PDU_TAG_DVBCI_EVT                       = 31
EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL    = 32
EXP_PDU_TAG_COL_PROT_TEXT                   = 33

class TagField(StrField):
    def __init__(self, name, default):
        StrField.__init__(self, name, default)

    def m2i(self, pkt, x):
        tag_type, tag_len = struct.unpack_from('!HH', x)
        x = x[4:]
        if tag_len > len(x):
            # XXX error?
            return
        tag_data, x = x[:tag_len], x[tag_len:]
        return[tag_type, tag_data]

    def i2m(self, pkt, x):
        tag_type, tag_data = x
        tag_len = len(tag_data)
        return struct.pack('!HH', tag_type, tag_len) + tag_data

class TagsField(StrField):
    islist = 1
    def __init__(self, name, default):
        StrField.__init__(self, name, default)

    def m2i(self, pkt, x):
        tags = []
        while len(x) >= 4:
            tag_type, tag_len = struct.unpack_from('!HH', x)
            x = x[4:]
            if tag_len > len(x):
                # XXX error?
                break
            tag_data, x = x[:tag_len], x[tag_len:]
            tag = [tag_type, tag_data]
            tags.append(tag)
            if tag_type == 0:
                break
        return tags

    def _convert_data(self, tag_type, tag_data):
        if type(tag_data) is int:
            return struct.pack('!I', tag_data)
        return tag_data

    def i2m(self, pkt, x):
        assert type(x) is list, "Not a list: %r (%r)" % (x, type(x))
        s = b''
        for tag in x:
            tag_type, tag_data = tag
            tag_data = self._convert_data(tag_type, tag_data)
            tag_len = len(tag_data)
            s += struct.pack('!HH', tag_type, tag_len) + tag_data
        return s

class WiresharkUpperPdu(Packet):
    name = "WiresharkUpperPdu"
    fields_desc = [ TagsField("tags", []) ]

udp_bootp = WiresharkUpperPdu(tags = [
        (EXP_PDU_TAG_DISSECTOR_TABLE_NAME, b'udp.port'),
        #(EXP_PDU_TAG_PORT_TYPE, 3), # UDP (3)
        #(EXP_PDU_TAG_DST_PORT, 68), # bootp
        (EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL, 67), # bootp
        (EXP_PDU_TAG_END_OF_OPT, b''),
    ])

ip_udp = WiresharkUpperPdu(tags = [
        (EXP_PDU_TAG_DISSECTOR_TABLE_NAME, b'ip.proto'),
        (EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL, 17), # IP_PROTO_UDP
        (EXP_PDU_TAG_END_OF_OPT, b''),
    ])

def make_pcap(filename, pkt):
    # Link Type: Wireshark Upper PDU export (252)
    wrpcap(filename, pkt, linktype=252)

parser = argparse.ArgumentParser()
parser.add_argument("filename")

def main():
    args = parser.parse_args()
    filename = args.filename
    output_filename = "%s.pcap" % filename
    assert not filename.endswith('.pcap')

    pcap_data = open(filename, 'rb').read()
    pkt = udp_bootp/pcap_data
    pkt = ip_udp/pcap_data
    make_pcap(output_filename, pkt)

if __name__ == '__main__':
    main()
