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
Async DNS server.

- UDP + TCP listeners (both on same host:port)
- Zone configuration loaded from JSON
- Pluggable resolver callback
- Transport-agnostic: uses dns_codec for all packet work
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
    "Zone",
    "DNSRequestHandler",
    "DNSServer",
    "start_dns_server",
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
    get_event_loop, start_server, DatagramProtocol, run, CancelledError
)
from typing import Callable, Dict, List, Optional, Tuple, Any
from struct import pack, unpack
from json import loads, load
from socket import inet_aton

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
        CNAMERecord,
        NSRecord,
        PTRRecord,
        MXRecord,
        TXTRecord,
        SRVRecord,
        SOARecord,
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
        CNAMERecord,
        NSRecord,
        PTRRecord,
        MXRecord,
        TXTRecord,
        SRVRecord,
        SOARecord,
        CAARecord,
    )
    from codec import codec


# ---------------------------------------------------------------------------
# Zone loader: build resource records from a JSON zone file
# ---------------------------------------------------------------------------
#
# JSON zone format example:
# {
#   "example.com": {
#     "A":    ["93.184.216.34"],
#     "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
#     "MX":   [{"preference": 10, "exchange": "mail.example.com"}],
#     "NS":   ["ns1.example.com", "ns2.example.com"],
#     "TXT":  ["v=spf1 include:_spf.example.com ~all"],
#     "CNAME": "www.example.com",
#     "SOA": {
#       "mname": "ns1.example.com", "rname": "hostmaster.example.com",
#       "serial": 2024010101, "refresh": 3600, "retry": 900,
#       "expire": 604800, "minimum": 300
#     },
#     "CAA": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}],
#     "SRV": [{"priority": 10, "weight": 20, "port": 5060, "target": "sip.example.com"}]
#   }
# }

def _build_rdata(rtype: int, value: Any) -> Optional[object]:
    if rtype == RecordType.A:
        return ARecord(value)
    if rtype == RecordType.AAAA:
        return AAAARecord(value)
    if rtype == RecordType.CNAME:
        return CNAMERecord(value)
    if rtype == RecordType.NS:
        return NSRecord(value)
    if rtype == RecordType.PTR:
        return PTRRecord(value)
    if rtype == RecordType.MX:
        return MXRecord(value["preference"], value["exchange"])
    if rtype == RecordType.TXT:
        s = value.encode("utf-8") if isinstance(value, str) else value
        return TXTRecord([s])
    if rtype == RecordType.SRV:
        return SRVRecord(value["priority"], value["weight"],
                         value["port"], value["target"])
    if rtype == RecordType.SOA:
        return SOARecord(**value)
    if rtype == RecordType.CAA:
        return CAARecord(value["flags"], value["tag"], value["value"])
    return None


_TYPE_MAP = {
    "A": RecordType.A,
    "AAAA": RecordType.AAAA,
    "CNAME": RecordType.CNAME,
    "NS": RecordType.NS,
    "PTR": RecordType.PTR,
    "MX": RecordType.MX,
    "TXT": RecordType.TXT,
    "SRV": RecordType.SRV,
    "SOA": RecordType.SOA,
    "CAA": RecordType.CAA,
}


class Zone:
    """
    Represents an in-memory DNS zone storing resource records indexed by (name, type).
    """

    def __init__(self, ttl: int = 300):
        self._records: Dict[Tuple[str, int], List[DNSResourceRecord]] = {}
        self.default_ttl = ttl

    def add(self, name: str, rtype: int, rdata: Any, ttl: Optional[int] = None):
        """
        Add a DNS record to the zone.

        Args:
            name: Domain name.
            rtype: DNS record type.
            rdata: Record data (raw or structured).
            ttl: Optional time-to-live; defaults to zone TTL.
        """

        key = (name.lower().rstrip("."), rtype)
        rr = DNSResourceRecord(
            name=name,
            rtype=rtype,
            rclass=RecordClass.IN,
            ttl=ttl if ttl is not None else self.default_ttl,
            rdata=_build_rdata(rtype, rdata),
        )
        self._records.setdefault(key, []).append(rr)

    def lookup(self, name: str, qtype: int) -> List[DNSResourceRecord]:
        """
        Lookup DNS records by name and type.

        Returns all matching records, or all types if qtype is ANY.
        """

        name_key = name.lower().rstrip(".")
        if qtype == RecordType.ANY:
            result = []
            for (n, t), rrs in self._records.items():
                if n == name_key:
                    result.extend(rrs)
            return result
        return self._records.get((name_key, qtype), [])

    @classmethod
    def from_dict(cls, data: dict, ttl: int = 300) -> "Zone":
        """
        Build a Zone from a dictionary structure.

        The input dictionary maps domain names to record definitions.

        Args:
            data: Dictionary containing DNS records.
            ttl: Default TTL applied when not specified.

        Returns:
            A populated Zone instance.
        """

        zone = cls(ttl)
        for name, records in data.items():
            for type_str, values in records.items():
                rtype = _TYPE_MAP.get(type_str.upper())
                if rtype is None:
                    continue
                ttl_val = records.get("ttl", ttl)
                if isinstance(values, list):
                    for v in values:
                        zone.add(name, rtype, v, ttl_val)
                else:
                    zone.add(name, rtype, values, ttl_val)
        return zone

    @classmethod
    def from_json(cls, path: str, ttl: int = 300) -> "Zone":
        """
        Load a Zone from a JSON file.

        Args:
            path: Path to the JSON file.
            ttl: Default TTL applied when not specified.

        Returns:
            A populated Zone instance.
        """

        with open(path, "r", encoding="utf-8") as f:
            data = load(f)
        return cls.from_dict(data, ttl)

    @classmethod
    def from_json_string(cls, json_str: str, ttl: int = 300) -> "Zone":
        """
        Build a Zone from a JSON string.

        Args:
            json_str: JSON string containing DNS records.
            ttl: Default TTL applied when not specified.

        Returns:
            A populated Zone instance.
        """

        return cls.from_dict(loads(json_str), ttl)


# ---------------------------------------------------------------------------
# Request handler (transport-agnostic)
# ---------------------------------------------------------------------------

ResolverCallback = Callable[[DNSMessage], Optional[DNSMessage]]


def _make_response(
    query_msg: DNSMessage,
    answers: List[DNSResourceRecord],
    rcode: int = ResponseCode.NOERROR,
    aa: int = 0,
) -> DNSMessage:
    response = DNSMessage(
        header=DNSHeader(
            transaction_id=query_msg.header.transaction_id,
            flags=DNSFlags(
                qr=1,
                opcode=query_msg.header.flags.opcode,
                aa=aa,
                rd=query_msg.header.flags.rd,
                ra=1,
                rcode=rcode,
            ),
            question_count=len(query_msg.questions),
            answer_count=len(answers),
        ),
        questions=query_msg.questions,
        answers=answers,
    )
    return response


class DNSRequestHandler:
    """
    Handles DNS request/response logic.
    Completely decoupled from transport (UDP/TCP).

    Priority:
      1. Custom resolver callback (if set)
      2. Zone lookup
      3. NXDOMAIN
    """

    def __init__(self, zone: Optional[Zone] = None,
                 resolver: Optional[ResolverCallback] = None):
        self.zone = zone
        self.resolver = resolver

    def handle(self, raw: bytes) -> Optional[bytes]:
        """
        Takes raw DNS query bytes.
        Returns raw DNS response bytes, or None if the packet is invalid.
        """

        try:
            query_msg = codec.decode(raw)
        except Exception as e:
            return None

        if query_msg.header.flags.qr != 0:
            return None

        if self.resolver is not None:
            try:
                response_msg = self.resolver(query_msg)
                if response_msg is not None:
                    return codec.encode(response_msg)
            except Exception:
                pass

        if self.zone is not None:
            answers: List[DNSResourceRecord] = []
            nxdomain = True

            for q in query_msg.questions:
                rrs = self.zone.lookup(q.name, q.qtype)
                if rrs:
                    nxdomain = False
                    answers.extend(rrs)
                else:
                    any_rrs = self.zone.lookup(q.name, RecordType.ANY)
                    if any_rrs:
                        nxdomain = False

            rcode = ResponseCode.NXDOMAIN if nxdomain else ResponseCode.NOERROR
            response = _make_response(query_msg, answers, rcode=rcode, aa=1)
            return codec.encode(response)

        response = _make_response(query_msg, [], rcode=ResponseCode.SERVFAIL)
        return codec.encode(response)


# ---------------------------------------------------------------------------
# Asyncio UDP server protocol
# ---------------------------------------------------------------------------

class _DNSUDPProtocol(DatagramProtocol):
    """
    Asyncio DatagramProtocol handling incoming DNS queries over UDP.
    """

    def __init__(self, handler: DNSRequestHandler):
        self._handler = handler
        self.transport = None

    def connection_made(self, transport):
        """
        Store the transport used to send and receive UDP datagrams.
        """

        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        """
        Handle an incoming DNS datagram.

        Decodes the query, delegates processing to the handler, and sends
        the response back to the client. If the response exceeds 512 bytes,
        it is truncated according to DNS UDP limitations.

        Args:
            data: Raw DNS query bytes.
            addr: Client address tuple.
        """

        response = self._handler.handle(data)
        if response:
            if len(response) > 512:
                msg = codec.decode(response)
                msg.header.flags.tc = 1
                msg.answers = []
                msg.header.answer_count = 0
                response = codec.encode(msg)
            self.transport.sendto(response, addr)


# ---------------------------------------------------------------------------
# Asyncio TCP connection handler
# ---------------------------------------------------------------------------

async def _tcp_connection_handler(
    reader, writer, handler: DNSRequestHandler
) -> None:
    try:
        length_bytes = await reader.readexactly(2)
        length = unpack(">H", length_bytes)[0]
        data = await reader.readexactly(length)

        response = handler.handle(data)
        if response:
            writer.write(pack(">H", len(response)) + response)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# High-level server starter
# ---------------------------------------------------------------------------

class DNSServer:
    """
    Async DNS server binding both UDP and TCP on the same host:port.

    Usage:
        zone = Zone.from_json("zone.json")
        server = DNSServer(zone=zone, host="0.0.0.0", port=5353)
        await server.start()
    """

    def __init__(self,
                 zone: Optional[Zone] = None,
                 resolver: Optional[ResolverCallback] = None,
                 host: str = "0.0.0.0",
                 port: int = 5353):
        self.host = host
        self.port = port
        self._handler = DNSRequestHandler(zone=zone, resolver=resolver)
        self._udp_transport = None
        self._tcp_server = None

    async def start(self) -> None:
        """
        Start the DNS server.

        Initializes both UDP and TCP endpoints on the configured host and port.
        """

        loop = get_event_loop()

        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSUDPProtocol(self._handler),
            local_addr=(self.host, self.port),
        )

        handler = self._handler
        self._tcp_server = await start_server(
            lambda r, w: _tcp_connection_handler(r, w, handler),
            self.host,
            self.port,
        )

        print(f"[DNS] Listening on {self.host}:{self.port} (UDP + TCP)")

    async def serve_forever(self) -> None:
        """
        Start the server and serve requests indefinitely.

        This method blocks until the server is stopped.
        """

        await self.start()
        async with self._tcp_server:
            await self._tcp_server.serve_forever()

    def close(self) -> None:
        """
        Close the UDP transport and TCP server.
        """

        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_server:
            self._tcp_server.close()


async def start_dns_server(
    host: str = "0.0.0.0",
    port: int = 5353,
    zone: Optional[Zone] = None,
    resolver: Optional[ResolverCallback] = None,
) -> DNSServer:
    """
    Convenience function to start and return a running DNSServer.
    """

    server = DNSServer(zone=zone, resolver=resolver, host=host, port=port)
    await server.start()
    return server
