#!/usr/bin/env python3
import socket
import argparse
import codecs
import struct
import random
import string
import secrets
import shlex
import hashlib

NAP_LOGIN = 0x2
NAP_MKUSER = 0x7
NAP_UNOK = 0x8
NAP_LOGIN = 0x2
NAP_LOGSUCCESS = 0x3
NAP_BROWSE = 0xD3
NAP_RBROWSE = 0xD4
NAP_DBROWSE = 0xD5
NAP_DGET = 0xCB
NAP_SGET = 0xCC
NAP_TELL = 0xCD
NAP_NGET = 0xCE

TARGET_USER = "nooopster"
TARGET_FILE = "\\shared\\nooopster"


def recvall(s, num_bytes):
    b = b""
    while len(b) < num_bytes:
        r = s.recv(num_bytes - len(b))
        if r is None or len(r) == 0:
            break
        b += r
    assert len(b) > 0, "failed to recv"
    return b


def int_to_ip(x):
    return "%d.%d.%d.%d" % (
        (x >> 0) & 0xFF,
        (x >> 8) & 0xFF,
        (x >> 16) & 0xFF,
        (x >> 24) & 0xFF,
    )


class ServerInteraction:
    def __init__(self, s):
        self._s = s

    def send(self, code, msg=b""):
        if type(msg) is str:
            msg = msg.encode("utf-8")
        hdr = struct.pack("<HH", len(msg), code)
        # print(("[send] %03d" % code) + (": %s" % msg if len(msg) > 0 else ""))
        self._s.send(hdr)
        self._s.send(msg)

    def recv(self):
        msg_len, code = struct.unpack("<HH", recvall(self._s, 4))
        msg = b""
        if msg_len > 0:
            msg = recvall(self._s, msg_len).decode("utf-8")
        # print(("[recv] %03d" % code) + (": %s" % msg if len(msg) > 0 else ""))
        return (code, msg)

    def recv_special(self, end_msg_codes):
        # messages not in end_msg_codes are discarded
        while True:
            c, m = self.recv()
            if c in end_msg_codes:
                return c, m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", default='')
    args = ap.parse_args()

    # First connect to metaserver to get server address (which should be 192.168.5.1:8888)
    print("connecting to metaserver")
    metaserver = ("192.168.5.1", 8875)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(metaserver)
    server_url = codecs.utf_8_decode(s.recv(1024))[0]
    server = server_url.strip().split(":")
    server = server[0], int(server[1])
    print("metaserver says: " + repr(server))
    assert server == ('192.168.5.1', 8888), "metaserver address changed"

    # Next connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(server)
    serv = ServerInteraction(s)

    # Login
    if args.user != '':
        uname = args.user
    else:
        uname = "user%d" % (random.getrandbits(8))
    serv.send(NAP_MKUSER, uname)
    c, _ = serv.recv()
    assert c == NAP_UNOK, "username check failed!"
    client_info = "nooopster-v0.0.0"
    data_port = 8080
    password = "".join(secrets.choice(string.ascii_letters) for i in range(8))
    serv.send(NAP_LOGIN, '%s %s %d "%s" 0' % (uname, password, data_port, client_info))
    c, _ = serv.recv()
    if c != NAP_LOGSUCCESS:
        print('PUBLIC: login failed')
        exit(1)
    assert c == NAP_LOGSUCCESS, "login failed"
    print("login ok")

    # Search nooopster's files
    serv.send(NAP_BROWSE, TARGET_USER)
    files = {}
    while True:
        c, m = serv.recv()
        if c == NAP_RBROWSE:
            peer_uname, fname, md5, size, bitrate, freq, time = shlex.split(m)
            files[fname] = (peer_uname, md5, size, bitrate, freq, time)
            # print("browse result: " + repr(m))
            continue
        elif c == NAP_DBROWSE:
            print("end of browse. client nick, IP: " + repr(m))
            break
        else:
            # Other message types are discarded
            pass

    if not (TARGET_FILE in files):
        print('PUBLIC: target file not found in users file list')
        exit(1)
    assert TARGET_FILE in files

    try:
        # Attempt to get file
        serv.send(NAP_DGET, '%s "%s"' % (TARGET_USER, TARGET_FILE))
        c, m = serv.recv_special([NAP_SGET, NAP_NGET])
        assert c == NAP_SGET, "get file failed"
        peer_uname, peer_ip, peer_port, fname, md5, linespeed = shlex.split(m)
        fsize = files[TARGET_FILE][2]  # string of filesize in decimal

        # Connect to peer to download file
        peer_ip_str = int_to_ip(int(peer_ip))
        peer_port = int(peer_port)
        print("server reports ip addr of user is: " + peer_ip_str)
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.connect((peer_ip_str, peer_port))

        # Receive the '1' byte
        print("receiving ascii '1' byte")
        b = peer.recv(1)
        assert b == b"1"
        peer.send(b"GET")
        peer.send(('%s "%s" 0' % (uname, TARGET_FILE)).encode("utf-8"))

        # Receive file length string
        print("receiving filesize")
        data = recvall(peer, len(fsize)).decode("utf-8")
        assert fsize == data, "invalid file size, expected %s got %s" % (
            repr(fsize),
            repr(data),
        )
        data = recvall(peer, int(fsize))

        # Check md5sum of data
        digest = hashlib.md5(data).hexdigest()
        print("file hash: " + digest)
        assert digest == "cc852cef3cc4bbfc993ba055cca437fc", "invalid file hash!"
    except:
        print('PUBLIC: download failed')
        exit(1)

    print('PUBLIC: ok')

if __name__ == "__main__":
    main()
