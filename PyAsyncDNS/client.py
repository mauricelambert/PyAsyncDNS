#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements a basic asynchronous DNS client and server
#    with a feature to exfiltrate data through DNS.
#    Copyright (C) 2025, 2026  PyAsyncDNS

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
DNS async client.

Three levels:
  - send_udp_raw / send_tcp_raw : low-level forced transport
  - resolve()                    : RFC-compliant smart resolver
  - Helper functions             : resolve_a, resolve_aaaa, resolve_mx, etc.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This package implements a basic asynchronous DNS client and server
with a feature to exfiltrate data through DNS.
"""
__url__ = "https://github.com/mauricelambert/PyAsyncDNS"

__all__ = [
    "send_udp_raw",
    "send_tcp_raw",
    "build_query",
    "query",
    "query_udp",
    "query_tcp",
    "resolve_a",
    "resolve_aaaa",
    "resolve_cname",
    "resolve_mx",
    "resolve_ns",
    "resolve_txt",
    "resolve_srv",
    "resolve_ptr",
    "resolve_soa",
    "resolve_caa",
    "resolve_any",
    "resolve",
]

__license__ = "GPL-3.0 License"
__copyright__ = """
PyAsyncDNS  Copyright (C) 2025, 2026  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
copyright = __copyright__
license = __license__

from asyncio import (
    get_event_loop,
    wait_for,
    DatagramProtocol,
    Future,
    open_connection,
    TimeoutError as AsyncTimeoutError,
)
from random import randint
from struct import pack, unpack
from socket import inet_pton, AF_INET6
from typing import List, Optional, Tuple

if __package__:
    from .datatypes import (
        DNSMessage,
        DNSHeader,
        DNSFlags,
        DNSQuestion,
        DNSResourceRecord,
        RecordType,
        RecordClass,
        ResponseCode,
        ARecord,
        AAAARecord,
        MXRecord,
        TXTRecord,
        CNAMERecord,
        NSRecord,
        SRVRecord,
        SOARecord,
        PTRRecord,
        CAARecord,
    )
    from .codec import codec
else:
    from datatypes import (
        DNSMessage,
        DNSHeader,
        DNSFlags,
        DNSQuestion,
        DNSResourceRecord,
        RecordType,
        RecordClass,
        ResponseCode,
        ARecord,
        AAAARecord,
        MXRecord,
        TXTRecord,
        CNAMERecord,
        NSRecord,
        SRVRecord,
        SOARecord,
        PTRRecord,
        CAARecord,
    )
    from codec import codec


# ---------------------------------------------------------------------------
# Internal asyncio UDP protocol
# ---------------------------------------------------------------------------

class _UDPClientProtocol(DatagramProtocol):
    """
    Asyncio DatagramProtocol implementation for sending a single UDP packet and receiving a response.
    """

    def __init__(self, packet: bytes, future: Future):
        self._packet = packet
        self._future = future
        self.transport = None

    def connection_made(self, transport):
        """
        Connection Callbacks: asyncio.BaseProtocol.connection_made

        Called when the UDP connection is established; sends the packet immediately.
        """

        self.transport = transport
        transport.sendto(self._packet)

    def datagram_received(self, data: bytes, addr):
        """
        Connection Callbacks: asyncio.DatagramProtocol.datagram_received

        Handle an incoming datagram and set the result on the Future.
        """

        if not self._future.done():
            self._future.set_result(data)
        self.transport.close()

    def error_received(self, exc: OSError):
        """
        Connection Callbacks: asyncio.DatagramProtocol.error_received

        Handle a transport-level error and propagate it to the Future.
        """

        if not self._future.done():
            self._future.set_exception(exc)
        if self.transport:
            self.transport.close()

    def connection_lost(self, exc: Exception):
        """
        Connection Callbacks: asyncio.BaseProtocol.connection_lost

        Called when the connection is closed; sets an exception if one occurred.
        """

        if exc and not self._future.done():
            self._future.set_exception(exc)


# ---------------------------------------------------------------------------
# Low-level transport: FORCED UDP
# ---------------------------------------------------------------------------

async def send_udp_raw(
    packet: bytes, server: str = "8.8.8.8", port: int = 53, timeout: float = 3.0
) -> bytes:
    """
    Send raw DNS wire-format bytes over UDP and return the raw response.
    Forces UDP regardless of message size.
    """

    loop = get_event_loop()
    future: Future = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UDPClientProtocol(packet, future),
        remote_addr=(server, port),
    )
    try:
        return await wait_for(future, timeout=timeout)
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# Low-level transport: FORCED TCP
# ---------------------------------------------------------------------------

async def send_tcp_raw(
    packet: bytes, server: str = "8.8.8.8", port: int = 53, timeout: float = 5.0
) -> bytes:
    """
    Send raw DNS wire-format bytes over TCP (2-byte length prefix) and return
    the raw response. Forces TCP regardless of message size.
    """

    prefixed = pack(">H", len(packet)) + packet
    try:
        reader, writer = await wait_for(
            open_connection(server, port), timeout=timeout
        )
    except AsyncTimeoutError:
        raise TimeoutError("TCP connection timed out")

    writer.write(prefixed)
    await writer.drain()

    length_bytes = await reader.readexactly(2)
    response_length = unpack(">H", length_bytes)[0]
    response = await reader.readexactly(response_length)

    writer.close()
    await writer.wait_closed()
    return response


# ---------------------------------------------------------------------------
# Message builder helpers
# ---------------------------------------------------------------------------

def build_query(
    name: str,
    qtype: int = RecordType.A,
    qclass: int = RecordClass.IN,
    transaction_id: Optional[int] = None,
    rd: int = 1,
) -> bytes:
    """
    Build a standard DNS query packet (wire format).
    """

    tid = randint(0, 0xFFFF) if transaction_id is None else transaction_id
    msg = DNSMessage(
        header=DNSHeader(
            transaction_id=tid,
            flags=DNSFlags(qr=0, opcode=0, rd=rd),
            question_count=1,
        ),
        questions=[DNSQuestion(name, qtype, qclass)],
    )
    return codec.encode(msg)


# ---------------------------------------------------------------------------
# RFC-compliant smart resolver
# ---------------------------------------------------------------------------

async def query(
    name: str,
    qtype: int = RecordType.A,
    server: str = "8.8.8.8",
    port: int = 53,
    timeout: float = 5.0,
    qclass: int = RecordClass.IN,
) -> DNSMessage:
    """
    RFC-compliant query:
      - Uses UDP first (<=512 bytes).
      - If TC (truncated) flag is set, retries over TCP.
      - Falls back to TCP if the query itself exceeds 512 bytes.
    Returns the decoded DNSMessage.
    """

    packet = build_query(name, qtype, qclass)

    if len(packet) > 512:
        raw = await send_tcp_raw(packet, server, port, timeout)
        return codec.decode(raw)

    raw = await send_udp_raw(packet, server, port, timeout)
    msg = codec.decode(raw)

    if msg.header.flags.tc:
        raw = await send_tcp_raw(packet, server, port, timeout)
        msg = codec.decode(raw)

    return msg


# ---------------------------------------------------------------------------
# Forced-transport query functions (bypass RFC size selection)
# ---------------------------------------------------------------------------

async def query_udp(
    name: str,
    qtype: int = RecordType.A,
    server: str = "8.8.8.8",
    port: int = 53,
    timeout: float = 3.0,
    transaction_id: Optional[int] = None,
) -> DNSMessage:
    """
    Force UDP regardless of packet size.
    """

    packet = build_query(name, qtype, transaction_id=transaction_id)
    raw = await send_udp_raw(packet, server, port, timeout)
    return codec.decode(raw)


async def query_tcp(
    name: str,
    qtype: int = RecordType.A,
    server: str = "8.8.8.8",
    port: int = 53,
    timeout: float = 5.0,
    transaction_id: Optional[int] = None,
) -> DNSMessage:
    """
    Force TCP regardless of packet size.
    """

    packet = build_query(name, qtype, transaction_id=transaction_id)
    raw = await send_tcp_raw(packet, server, port, timeout)
    return codec.decode(raw)


# ---------------------------------------------------------------------------
# Helper: extract typed answers
# ---------------------------------------------------------------------------

def _answers_of_type(msg: DNSMessage, rtype: int) -> List[DNSResourceRecord]:
    return [rr for rr in msg.answers if rr.rtype == rtype]


# ---------------------------------------------------------------------------
# High-level helper functions
# ---------------------------------------------------------------------------

async def resolve_a(
    name: str, server: str = "8.8.8.8", port: int = 53,
) -> List[str]:
    """
    Resolve A records -> list of IPv4 strings.
    """

    msg = await query(name, RecordType.A, server, port)
    return [rr.rdata.address for rr in _answers_of_type(msg, RecordType.A)
            if isinstance(rr.rdata, ARecord)]


async def resolve_aaaa(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> List[str]:
    """
    Resolve AAAA records -> list of IPv6 strings.
    """

    msg = await query(name, RecordType.AAAA, server, port)
    return [rr.rdata.address for rr in _answers_of_type(msg, RecordType.AAAA)
            if isinstance(rr.rdata, AAAARecord)]


async def resolve_cname(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> List[str]:
    """
    Resolve CNAME records -> list of canonical name strings.
    """

    msg = await query(name, RecordType.CNAME, server, port)
    return [rr.rdata.target for rr in _answers_of_type(msg, RecordType.CNAME)
            if isinstance(rr.rdata, CNAMERecord)]


async def resolve_mx(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> List[Tuple[int, str]]:
    """
    Resolve MX records -> list of (preference, exchange) tuples, sorted by preference.
    """

    msg = await query(name, RecordType.MX, server, port)
    results = [
        (rr.rdata.preference, rr.rdata.exchange)
        for rr in _answers_of_type(msg, RecordType.MX)
        if isinstance(rr.rdata, MXRecord)
    ]
    return sorted(results, key=lambda x: x[0])


async def resolve_ns(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> List[str]:
    """
    Resolve NS records -> list of nameserver strings.
    """

    msg = await query(name, RecordType.NS, server, port)
    return [rr.rdata.nameserver for rr in _answers_of_type(msg, RecordType.NS)
            if isinstance(rr.rdata, NSRecord)]


async def resolve_txt(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> List[str]:
    """
    Resolve TXT records -> list of decoded text strings (segments joined).
    """

    msg = await query(name, RecordType.TXT, server, port)
    results = []
    for rr in _answers_of_type(msg, RecordType.TXT):
        if isinstance(rr.rdata, TXTRecord):
            results.append(b"".join(rr.rdata.strings).decode("utf-8", errors="replace"))
    return results


async def resolve_srv(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> List[SRVRecord]:
    """
    Resolve SRV records -> list of SRVRecord objects.
    """

    msg = await query(name, RecordType.SRV, server, port)
    return [rr.rdata for rr in _answers_of_type(msg, RecordType.SRV)
            if isinstance(rr.rdata, SRVRecord)]


async def resolve_ptr(
    ip: str, server: str = "8.8.8.8", port: int = 53
) -> List[str]:
    """
    Reverse DNS lookup (PTR).
    Automatically converts IPv4 (e.g. "8.8.8.8") to "8.8.8.8.in-addr.arpa".
    """

    parts = ip.split(".")
    if len(parts) == 4:
        arpa = ".".join(reversed(parts)) + ".in-addr.arpa"
    else:
        raw = inet_pton(AF_INET6, ip)
        nibbles = "".join(f"{b:02x}" for b in raw)
        arpa = ".".join(reversed(nibbles)) + ".ip6.arpa"

    msg = await query(arpa, RecordType.PTR, server, port)
    return [rr.rdata.ptrdname for rr in _answers_of_type(msg, RecordType.PTR)
            if isinstance(rr.rdata, PTRRecord)]


async def resolve_soa(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> Optional[SOARecord]:
    """
    Resolve SOA record -> SOARecord or None.
    """

    msg = await query(name, RecordType.SOA, server, port)
    for rr in _answers_of_type(msg, RecordType.SOA):
        if isinstance(rr.rdata, SOARecord):
            return rr.rdata
    return None


async def resolve_caa(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> List[CAARecord]:
    """
    Resolve CAA records -> list of CAARecord objects.
    """

    msg = await query(name, RecordType.CAA, server, port)
    return [rr.rdata for rr in _answers_of_type(msg, RecordType.CAA)
            if isinstance(rr.rdata, CAARecord)]


async def resolve_any(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> DNSMessage:
    """
    Send ANY query and return the full DNSMessage.
    """

    return await query(name, RecordType.ANY, server, port)


async def resolve(
    name: str, server: str = "8.8.8.8", port: int = 53
) -> List[str]:
    """
    Smart resolve: tries A first, then AAAA.
    Returns all IPs (v4 first, then v6).
    """

    ipv4 = await resolve_a(name, server, port)
    ipv6 = await resolve_aaaa(name, server, port)
    return ipv4 + ipv6
