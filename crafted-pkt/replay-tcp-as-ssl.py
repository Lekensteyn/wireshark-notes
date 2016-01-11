#!/usr/bin/env python2
"""
Wraps an unencrypted TCP protocol in SSL.

Reads a pcap file containing a single unencrypted TCP stream and replays the
data over a SSL-encrypted channel (internal SSL server started for this
purpose). You must create server.pem first.

Best combined with src/sslkeylog.sh for extracting the pre-master secret (or
force a certain cipher).

Originally used to generate a pcap for Wireshark bug 11990 from the
evidence01.pcap file from
http://forensicscontest.com/2009/09/25/puzzle-1-anns-bad-aim

Copyright (C) 2016 Peter Wu <peter@lekensteyn.nl>
"""
import argparse, socket, ssl, sys
from threading import Thread, Condition

# Meh, scapy 2.3.1 still does not support Py3... There is scapy3k though.
from scapy.all import *
try:
    from queue import Queue
except ImportError:
    from Queue import Queue

address = ('127.0.0.1', 4433)
parser = argparse.ArgumentParser()
parser.add_argument("--key", default="server.pem",
        help="Private SSL key (default %(default)s)")
parser.add_argument("--cert", default="server.pem",
        help="SSL certificate (default %(default)s)")
parser.add_argument("--ciphers",
        help="SSL cipher list (see OpenSSL ciphers, default not restricted)")
parser.add_argument("pcap_file", help="Pcap file with single TCP stream")
parser.add_argument("pcap_srvport", type=int, help="Server port in pcap")

def get_server_sock(q, c, key, cert):
    c.acquire()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)
        sock.listen(1)
    except:
        q.put(None)
        raise
    finally:
        c.notify()
        c.release()
    try:
        conn, addr = sock.accept()
        print("Client: %r" % (addr,))
        conn = ssl.wrap_socket(conn, key, cert, True)
        q.put(conn)
    except:
        q.put(None)
        raise

def get_client_sock(q, ciphers):
    try:
        csock = socket.create_connection(address)
        print("Client connected to server at: %r" % csock)
        csock = ssl.wrap_socket(csock, ciphers=ciphers)
        q.put(csock)
    except:
        q.put(None)
        raise

def main():
    args = parser.parse_args()

    # Connect in separate threads to avoid a deadlock due to the SSL handshake
    # waiting for a reply while the other connection still needs to be wrapped.
    server_queue = Queue()
    client_queue = Queue()
    cond = Condition()
    server_thread = Thread(target=get_server_sock, name='Server',
            args=(server_queue, cond, args.key, args.cert))
    client_thread = Thread(target=get_client_sock, name='Client',
            args=(client_queue, args.ciphers))
    cond.acquire()
    server_thread.start()
    cond.wait()
    cond.release()
    client_thread.start()

    server_thread.join()
    client_thread.join()
    ssock = server_queue.get()
    csock = client_queue.get()
    print("Server: %r" % ssock)
    print("Client: %r" % csock)
    if not ssock or not csock:
        sys.exit(1)

    pkts = rdpcap(args.pcap_file)
    for p in pkts:
        data = str(p[TCP].payload)
        if not data:
            print("Skipping empty packet %r", p[TCP])
            continue
        if p[TCP].sport == args.pcap_srvport:
            sender, receiver = ssock, csock
        else:
            sender, receiver = csock, ssock
        print("Sending packet %r" % p[TCP])
        sender.sendall(data)
        remaining = len(data)
        while remaining > 0:
            remaining -= len(receiver.recv(remaining))

    csock.close()
    ssock.close()

    print("Final!")

if __name__ == '__main__':
    main()
