#!/usr/bin/env python
#
# Replay a communication, splitting data at a certain chunk sizes
# (defaults to 2). This can be used to test reassembly for example.
#
# Copyright (C) 2014 Peter Wu <peter@lekensteyn.nl>

# Usage (assuming a capture file with TCP stream 0 at loopback interface lo)
#     dumpcap -i lo -w split.pcapng
#     ./replay-chunks.py old-capture.pcapng
# Run ./replay-chunks.py --help for details

import socket
import sys
import os
from argparse import ArgumentParser
from subprocess import PIPE
from subprocess import Popen as _Popen
if hasattr(_Popen, '__exit__'):
    Popen = _Popen
else:
    class PopenClosable(_Popen):
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_value, traceback):
            self.stdout.close()
    Popen = PopenClosable
try:
    from subprocess import DEVNULL
except ImportError:
    # Python < 3.3 compatibility
    DEVNULL = open(os.devnull, 'w')

state = 'init'

def _is_marker(line):
    return all(c == '=' for c in line.strip())

def _dumpbytes(data):
    return ''.join([
        chr(x) if x >= 0x20 and x < 0x7f else '.'
            for x in data
    ])

class FollowParser(object):
    def __init__(self, chunk_size=2):
        self.state = self.state_find_begin
        self.addr = None
        self.sock_client = None
        self.sock_server = None
        self.chunk_size = chunk_size

    def add_data(self, data, is_reply):
        sock = self.sock_server if is_reply else self.sock_client
        othersock = self.sock_client if is_reply else self.sock_server
        for i in range(0, len(data), self.chunk_size):
            sock.sendall(data[i:i+self.chunk_size])
            othersock.recv(self.chunk_size)
        print('{}: {}'.format('S->C' if is_reply else 'C->S', _dumpbytes(data)))

    def state_find_begin(self, line):
        if _is_marker(line):
            self.state = self.state_find_node_1

    def state_find_node_1(self, line):
        if line.startswith('Node 1: '):
            host, port = line.split(' ')[-1].rsplit(':', 1)
            self.addr = (host, int(port))
            self.state = self.state_find_data
            self.open_sockets()

    def state_find_data(self, line):
        if _is_marker(line):
            self.state = self.state_done
            return
        is_reply = line.startswith('\t')
        data = bytearray.fromhex(line.strip())
        self.add_data(data, is_reply)

    def state_done(self, line):
        pass

    def open_sockets(self):
        svr = socket.socket()
        try:
            svr.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            svr.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                svr.bind(self.addr)
            except socket.error as e:
                host, port = self.addr
                print('bind({0}:{1}) failure: {2}'.format(host, port, e))
                self.addr = ('127.9.0.1', port)
                print('Falling back to {}:{}'.format(*self.addr))
                svr.bind(self.addr)
            svr.listen(1)
            self.sock_client = socket.socket()
            self.sock_client.connect(self.addr)
            self.sock_server, remote_addr = svr.accept()
        finally:
            svr.close()

    def feed_data(self, line):
        old_state = self.state
        self.state(line)
        # Return old state and new state
        return old_state, self.state

    def close(self):
        if self.sock_server:
            self.sock_server.close()
            self.sock_server = None
        if self.sock_client:
            self.sock_client.close()
            self.sock_client = None

def main(tshark_output, chunk_size):
    parser = FollowParser(chunk_size=chunk_size)
    try:
        for line in tshark_output:
            old_state, new_state = parser.feed_data(line)
            if new_state != old_state and old_state == parser.state_find_node_1:
                print('Found server node: {}:{}'.format(*parser.addr))
    finally:
        parser.close()

parser = ArgumentParser(description='Replay TCP capture')
parser.add_argument('-s', '--chunk-size', type=int, default=2,
                    help='Maximum size of each chunk (default %(default)d)')
parser.add_argument('file', help='Any capture format recognized by tshark')
if __name__ == '__main__':
    _args = parser.parse_args()
    _cmd = [
        'tshark',
        '-r',
        _args.file,
        '-q',
        '-z', 'follow,tcp,raw,0'
    ]
    with Popen(_cmd, stdin=DEVNULL, stdout=PIPE, universal_newlines=True) as p:
        main(p.stdout, chunk_size=_args.chunk_size)
