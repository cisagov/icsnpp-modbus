#!/usr/bin/env python3
"""Generate the trace in modbus_read_device_identification.pcap.b64 (stdlib only).

One Modbus/TCP connection with two Read Device Identification exchanges
(function 0x2B, MEI type 0x0E), laid out as in Modbus Application Protocol
Specification V1.1b3, section 6.21:

  tid 1: stream access (ReadDevId 01, object 0x00); the response reports
         conformity level 0x03 and carries objects 0x00, 0x01 and 0x02.
  tid 2: individual access (ReadDevId 04, object 0x01); the response reports
         conformity level 0x83 and carries object 0x01.

Usage: python3 modbus_read_device_identification.py | base64 -w 76 > modbus_read_device_identification.pcap.b64
"""

import struct
import sys

CLIENT = (bytes([192, 168, 1, 10]), 50200)
SERVER = (bytes([192, 168, 1, 20]), 502)


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def tcp_packet(src, dst, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = src[0] + dst[0] + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0, 0, 64, 6, 0, src[0], dst[0])
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ether = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return ether + ip + tcp + payload


def mbap(tid, unit, pdu):
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def objects(*items):
    out = b""
    for object_id, value in items:
        out += bytes([object_id, len(value)]) + value
    return out


SYN, ACK, PSH_ACK, FIN_ACK = 0x02, 0x10, 0x18, 0x11

messages = [
    (CLIENT, mbap(1, 1, bytes([0x2B, 0x0E, 0x01, 0x00]))),
    (SERVER, mbap(1, 1, bytes([0x2B, 0x0E, 0x01, 0x03, 0x00, 0x00, 0x03])
                  + objects((0x00, b"Example Vendor"), (0x01, b"EX-100"), (0x02, b"V1.2")))),
    (CLIENT, mbap(2, 1, bytes([0x2B, 0x0E, 0x04, 0x01]))),
    (SERVER, mbap(2, 1, bytes([0x2B, 0x0E, 0x04, 0x83, 0x00, 0x00, 0x01])
                  + objects((0x01, b"EX-100")))),
]

packets = []
cseq, sseq = 1000, 5000
packets.append(tcp_packet(CLIENT, SERVER, cseq, 0, SYN))
packets.append(tcp_packet(SERVER, CLIENT, sseq, cseq + 1, SYN | ACK))
cseq += 1
sseq += 1
packets.append(tcp_packet(CLIENT, SERVER, cseq, sseq, ACK))
for sender, payload in messages:
    if sender is CLIENT:
        packets.append(tcp_packet(CLIENT, SERVER, cseq, sseq, PSH_ACK, payload))
        cseq += len(payload)
    else:
        packets.append(tcp_packet(SERVER, CLIENT, sseq, cseq, PSH_ACK, payload))
        sseq += len(payload)
packets.append(tcp_packet(CLIENT, SERVER, cseq, sseq, FIN_ACK))
packets.append(tcp_packet(SERVER, CLIENT, sseq, cseq + 1, FIN_ACK))
packets.append(tcp_packet(CLIENT, SERVER, cseq + 1, sseq + 1, ACK))

out = sys.stdout.buffer
out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
for index, packet in enumerate(packets):
    ts = 1700000000 + index
    out.write(struct.pack("<IIII", ts, 0, len(packet), len(packet)))
    out.write(packet)
