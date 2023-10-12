#!/usr/bin/env python3
import argparse
import struct
# So slow... let's import what we need.
#from scapy.all import *
from scapy.config import conf
from scapy.fields import StrField
from scapy.packet import Packet
from scapy.utils import wrpcap

# From wsutil/exported_pdu_tlvs.h (used in epan/exported_pdu.h)
EXP_PDU_TAG_END_OF_OPT                      = 0
EXP_PDU_TAG_OPTIONS_LENGTH                  = 10
EXP_PDU_TAG_LINKTYPE                        = 11
EXP_PDU_TAG_DISSECTOR_NAME                  = 12
EXP_PDU_TAG_HEUR_DISSECTOR_NAME             = 13
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
EXP_PDU_TAG_TCP_INFO_DATA                   = 34
EXP_PDU_TAG_P2P_DIRECTION                   = 35
EXP_PDU_TAG_COL_INFO_TEXT                   = 36

# For backwards compatibility, since Wireshark v4.1.0rc0-197-ge5951765d8.
EXP_PDU_TAG_PROTO_NAME = EXP_PDU_TAG_DISSECTOR_NAME
EXP_PDU_TAG_HEUR_PROTO_NAME = EXP_PDU_TAG_HEUR_DISSECTOR_NAME


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
        # Wireshark pads some strings to align them at four bytes. Although not
        # strictly necessary for use in Wireshark, replicate it. See
        # https://gitlab.com/wireshark/wireshark/-/issues/19284
        tag_len = len(tag_data)
        if tag_type in (EXP_PDU_TAG_DISSECTOR_NAME,
                        EXP_PDU_TAG_HEUR_DISSECTOR_NAME,
                        EXP_PDU_TAG_DISSECTOR_TABLE_NAME) and (tag_len & 3):
            pad_len = 4 - (tag_len & 3)
            tag_data += pad_len * b'\0'
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

DLT_WIRESHARK_UPPER_PDU = 252
conf.l2types.register(DLT_WIRESHARK_UPPER_PDU, WiresharkUpperPdu)

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
    wrpcap(filename, pkt, linktype=DLT_WIRESHARK_UPPER_PDU)

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
