# Wireshark dissection and reassembly
Wireshark's current dissection engine and stream reassembly functionality has
been the same for a long time, but it is showing its age. This document
describes the current implementation (Wireshark 3.2.x), related research, and
attempts to provide a solution for identifies problems.

Status: **DRAFT**.

## Overview
The primary unit of work is a frame, sometimes referred to as packet. These are
passed to the frame dissector which will:

- Add metadata such as timing.
- Pass the buffer to the next dissector. The dissector is usually Ethernet or
  IP, depending on how the capture file was created.
- Once done, any post-dissectors will be invoked with the same buffer.

The "next dissector" above will typically parse some data, and pass the
remaining data to the next. This is the case for Ethernet -> IPv4/IPv6 -> TCP
for example. All of these are currently done serially, the next packet cannot be
processed until the current one is finished. One reason is that the dissection
of subsequent packets may depend on previous ones. This limits parallel
processing, something which is also made difficult due to implementation details
such as use of global data.

Aside from per-packet processing, dissectors may maintain state:

- The TCP dissector reconstructs flows, performing reassembly of TCP segments.
- The TLS dissector reconstructs a TLS handshake and uses the information to
  build a cipher for decrypting application data. This decrypted application
  data is remembered for later use.
- The DNS dissector remembers message identifiers to find retransmissions and to
  calculate response times.
- The WireGuard dissector processes handshake messages and creates a cipher for
  a session. Decrypted data is not saved due to memory usage concerns, instead
  decryption is performed every time the packet is accessed. This is possible
  because a single packet contains the counter value required for decryption.
  The TLS dissector on the other hand cannot read the counter from a TLS record.

Reliable TCP stream reassembly is required for proper functionality of
higher-level protocols. Typically, the initial part of a higher-level PDU (such
as the start of HTTP/1.1 headers) are aligned with a TCP segment payload. If all
headers fit in a single TCP segment, then the HTTP dissector is able to dissect
the full headers without further state. However, if the HTTP request is split
over multiple segments, then these segments have to be collected and merged
based on their sequence numbers. This introduces its own share of problems:

- TCP segments may be overlapping.
- TCP segments may appear out of order. Out-of-order SYN or (more likely) FIN
  may result in wrongly reconstructed streams
  ([Bug 16289](https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16289)).
- TCP segments may be missing from the capture file.
- TCP segments may be duplicated due to retransmission.
- TCP segments may be overlapping, and contain conflicting data. Either due to
  bitflips or malicious actors in a network.
- The packet capture could start in midst of a sessions. If multiple HTTP
  messages are sent over one stream, the start of a TCP segment may not
  coincidence with the start of a HTTP message. That means that the stream
  cannot be recovered from a naive assumption.

Assuming a mechanism that properly reassembles the above complete TCP stream
into a sequential stream, the higher-level protocols may bring additional
problems. Consider TLS:

- TLS records can be split over multiple TCP segments.
- Multiple TLS records may be present in one TCP segment.
- The start of a TLS record may not coincidence with the start of a TCP segment.
- Decrypted application data may not be uniquely identifiable by the frame
  number (the position of a packet in the capture file).

And after TLS, the next application data protocol may also bring additional
problems. Consider HTTP/2:

- HTTP/2 multiplexes a TCP/TLS stream into multiple logical streams which are
  contained in HTTP/2 frames.
- A single TLS record might contain multiple HTTP/2 stream frames which are
  identified by a 31-bit Stream Identifier.
- HTTP/2 stream frames may be split over multiple TLS records.
- The frame number may not uniquely identify a HTTP/2 frame.

Finally, all of the previous network protocols may not be useful to the
end-user. They may be more interested in data such as reconstructed HTML, CSS,
JavaScript, JSON, JPEG, etc. files. In those cases, they may not be interested
in the exact TCP segment. On the other hand, the start of a TCP segment, a TLS
record, or a HTTP/2 frame may be interesting for performance measurements. For
that to happen, precise tracking of the individual protocol data parts may be
necessary. This may be complicated by out-of-order receipt of TCP segments,
especially when multiple PDUs are in flight.

Wireshark has features to handle aggregates of individual packets:

- "Follow TCP Stream" reads through a whole capture and extracts a single TCP
  stream.
- "Export Objects" may be used to extract HTTP objects (HTML, CSS, etc.), IMF
  (email data from SMTP), etc.
- A Follow HTTP/2 Stream is available since Wireshark 3.2, but merges data from
  other streams in the reassembled packet
  ([Bug 16093](https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16093)).

The state tracking required for the above functionality requires resources,
trading off memory cost against CPU time. With new protocols such as QUIC and
HTTP/3, the complexity of decryption, providing stream reassembly and accurate
metadata such as timing seem to warrant significant dissection engine changes in
order to simplify the implementation of new features.

Large objects such as Docker image layers and videos also require more efficient
implementations:

- Memoization to speed up reassembly.
- Reduce memory usage by sharing buffers where possible.
- Consider folding or eliding fields. For example, a large object of hundreds of
  megabytes likely consists of several 100k TCP segments, displaying all of
  these in a single view is impossible.

## Ideas
To speed up processing, parallelism is needed. In the common case with no
malicious packets, packet processing should be postponed until flow
reconstruction has happened.


## Related work
This section covers other works from which lessons can potentially be learned.

### tcpflow
Passive TCP Reconstruction and Forensic Analysis with tcpflow, 2013-09
https://calhoun.nps.edu/bitstream/handle/10945/36026/NPS-CS-13-003.pdf

https://github.com/simsong/tcpflow

### binpac
binpac: A yacc for Writing Application Protocol Parsers, 2006-10
https://www.icsi.berkeley.edu/pubs/networking/binpacIMC06.pdf

https://github.com/zeek/binpac
