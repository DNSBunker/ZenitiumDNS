import asyncio
import hashlib
import socket
import struct
import sys

ROOT_IP = "10.53.0.1"
TLD_IP = "10.53.0.2"
TLD = b"deadtld"


def parse_name(data, off):
    labels = []
    while True:
        ln = data[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:
            raise ValueError("compressed qname")
        labels.append(bytes(data[off + 1:off + 1 + ln]))
        off += 1 + ln
    return labels, off


def enc_name(labels):
    out = b""
    for l in labels:
        out += bytes([len(l)]) + l
    return out + b"\x00"


def rr(name_labels, rtype, ttl, rdata):
    return enc_name(name_labels) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def soa_rdata(zone_labels):
    return enc_name([b"ns"] + zone_labels) + enc_name([b"hostmaster"] + zone_labels) + struct.pack("!IIIII", 1, 3600, 600, 86400, 300)


def ttl_for(labels, lo, hi):
    h = hashlib.blake2b(b".".join(labels), digest_size=4).digest()
    return lo + int.from_bytes(h, "big") % (hi - lo + 1)


def addr_for(labels):
    h = hashlib.blake2b(b".".join(labels), digest_size=4).digest()
    return bytes([10, 100 + (h[0] % 100), h[1], max(1, h[2])])


def answer(data, role):
    if len(data) < 12:
        return None
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if qd != 1:
        return None
    try:
        labels, off = parse_name(data, 12)
    except Exception:
        return None
    qtype, qclass = struct.unpack("!HH", data[off:off + 4])
    question = data[12:off + 4]
    llabels = [l.lower() for l in labels]
    edns = b""
    if ar >= 1:
        edns = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    answers, authority, additional = [], [], []
    rcode = 0
    aa = True
    if role == "root":
        if not llabels:
            if qtype == 2:
                answers.append(rr([], 2, 518400, enc_name([b"a", b"root-servers", b"net"])))
                additional.append(rr([b"a", b"root-servers", b"net"], 1, 518400, socket.inet_aton(ROOT_IP)))
            elif qtype == 6:
                answers.append(rr([], 6, 86400, soa_rdata([])))
            else:
                authority.append(rr([], 6, 86400, soa_rdata([])))
        elif llabels[-1] == TLD:
            aa = False
            authority.append(rr([TLD], 2, 172800, enc_name([b"ns", TLD])))
            additional.append(rr([b"ns", TLD], 1, 172800, socket.inet_aton(TLD_IP)))
        elif llabels[-2:] == [b"root-servers", b"net"] and qtype == 1:
            answers.append(rr(llabels, 1, 518400, socket.inet_aton(ROOT_IP)))
        else:
            rcode = 3
            authority.append(rr([], 6, 86400, soa_rdata([])))
    else:
        if not llabels or llabels[-1] != TLD:
            return struct.pack("!HHHHHH", ident, 0x8005, 1, 0, 0, 0) + question
        zone = [TLD]
        if llabels == [TLD]:
            if qtype == 2:
                answers.append(rr(zone, 2, 3600, enc_name([b"ns", TLD])))
            elif qtype == 6:
                answers.append(rr(zone, 6, 3600, soa_rdata(zone)))
            else:
                authority.append(rr(zone, 6, 300, soa_rdata(zone)))
        elif llabels[0].startswith(b"nx"):
            rcode = 3
            authority.append(rr(zone, 6, 300, soa_rdata(zone)))
        elif llabels == [b"ns", TLD] and qtype == 1:
            answers.append(rr(llabels, 1, 3600, socket.inet_aton(TLD_IP)))
        elif qtype == 1:
            answers.append(rr(labels, 1, ttl_for(llabels, 300, 3600), addr_for(llabels)))
        elif qtype == 28:
            answers.append(rr(labels, 28, ttl_for(llabels, 300, 3600), b"\xfd\x00" + b"\x00" * 10 + addr_for(llabels)))
        elif qtype == 16:
            answers.append(rr(labels, 16, ttl_for(llabels, 300, 3600), b"\x0bhello world"))
        else:
            authority.append(rr(zone, 6, 300, soa_rdata(zone)))
    rflags = 0x8000 | (0x0400 if aa else 0) | (flags & 0x0100) | rcode
    body = b"".join(answers) + b"".join(authority) + b"".join(additional)
    return struct.pack("!HHHHHH", ident, rflags, 1, len(answers), len(authority), len(additional) + (1 if edns else 0)) + question + body + edns


class Udp(asyncio.DatagramProtocol):
    def __init__(self, role):
        self.role = role

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            resp = answer(data, self.role)
        except Exception:
            resp = None
        if resp:
            self.transport.sendto(resp, addr)


async def tcp_handler(reader, writer, role):
    try:
        while True:
            hdr = await reader.readexactly(2)
            (ln,) = struct.unpack("!H", hdr)
            data = await reader.readexactly(ln)
            resp = answer(data, role)
            if resp:
                writer.write(struct.pack("!H", len(resp)) + resp)
                await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def main():
    role, ip = sys.argv[1], sys.argv[2]
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
    sock.bind((ip, 53))
    await loop.create_datagram_endpoint(lambda: Udp(role), sock=sock)
    server = await asyncio.start_server(lambda r, w: tcp_handler(r, w, role), ip, 53)
    async with server:
        await server.serve_forever()


asyncio.run(main())
