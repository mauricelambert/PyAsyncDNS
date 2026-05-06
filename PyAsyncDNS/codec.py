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
DNS wire-format encoder and decoder.

Handles all record types with full RFC compliance.
Completely decoupled from any socket/transport layer.
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
    "encode_name",
    "decode_name",
    "DNSCodec",
    "codec",
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

from struct import pack, unpack, pack_into
from typing import Tuple, List, Dict, Optional
from socket import inet_aton, inet_ntoa, inet_pton, inet_ntop, AF_INET6

if __package__:
    from .datatypes import (
        DNSHeader,
        DNSFlags,
        DNSQuestion,
        DNSMessage,
        DNSResourceRecord,
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
        RecordType,
        RecordClass,
    )
else:
    from datatypes import (
        DNSHeader,
        DNSFlags,
        DNSQuestion,
        DNSMessage,
        DNSResourceRecord,
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
        RecordType,
        RecordClass,
    )


# ---------------------------------------------------------------------------
# Domain name encoding / decoding (with compression support)
# ---------------------------------------------------------------------------

def encode_name(
    name: str,
    compression: Optional[Dict[str, int]] = None,
    offset: int = 0,
) -> bytes:
    """
    Encode a domain name to DNS wire format.
    Optionally uses/updates a compression dict (name -> offset in packet).
    """

    if not name or name == ".":
        return b"\x00"

    name = name.rstrip(".")
    labels = name.split(".")
    result = bytearray()
    current_name = name

    while labels:
        if compression is not None and current_name in compression:
            ptr = compression[current_name]
            result += pack(">H", 0xC000 | ptr)
            return bytes(result)

        label = labels[0]
        encoded_label = label.encode("ascii")
        if len(encoded_label) > 63:
            raise ValueError(f"Label too long: {label!r}")

        if compression is not None:
            compression[current_name] = offset + len(result)

        result += bytes([len(encoded_label)]) + encoded_label
        labels = labels[1:]
        current_name = ".".join(labels) if labels else ""

    result += b"\x00"
    return bytes(result)


def decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode a domain name from DNS wire format, supporting pointer compression.
    Returns (name, new_offset) where new_offset is just past the name field.
    """

    labels = []
    visited = set()
    end_offset = None

    while offset < len(data):
        if offset in visited:
            raise ValueError("DNS name compression loop detected")
        visited.add(offset)

        length = data[offset]
        length_C0 = length & 0xC0

        if length_C0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Truncated DNS compression pointer")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if end_offset is None:
                end_offset = offset + 2
            offset = ptr
            continue
        elif length_C0 != 0:
            raise ValueError(f"Invalid label length byte: {length:#x}")

        offset += 1

        if length == 0:
            if end_offset is None:
                end_offset = offset
            break

        label_bytes = data[offset: offset + length]
        labels.append(label_bytes.decode("ascii"))
        offset += length

    return ".".join(labels), end_offset


# ---------------------------------------------------------------------------
# RDATA encoders
# ---------------------------------------------------------------------------

def _encode_a(record: ARecord) -> bytes:
    return inet_aton(record.address)


def _encode_aaaa(record: AAAARecord) -> bytes:
    return inet_pton(AF_INET6, record.address)


def _encode_name_only(name: str, compression: Dict[str, int], offset: int) -> bytes:
    return encode_name(name, compression, offset)


def _encode_mx(record: MXRecord, compression: Dict[str, int], offset: int) -> bytes:
    return pack(">H", record.preference) + encode_name(record.exchange, compression, offset + 2)


def _encode_txt(record: TXTRecord) -> bytes:
    result = b""
    for s in record.strings:
        if isinstance(s, str):
            s = s.encode("utf-8")
        if len(s) > 255:
            raise ValueError("TXT string segment exceeds 255 bytes")
        result += bytes([len(s)]) + s
    return result


def _encode_srv(record: SRVRecord, compression: Dict[str, int], offset: int) -> bytes:
    return (
        pack(">HHH", record.priority, record.weight, record.port)
        + encode_name(record.target, compression, offset + 6)
    )


def _encode_soa(record: SOARecord, compression: Dict[str, int], offset: int) -> bytes:
    mname = encode_name(record.mname, compression, offset)
    rname = encode_name(record.rname, compression, offset + len(mname))
    return mname + rname + pack(">IIIII",
        record.serial, record.refresh, record.retry,
        record.expire, record.minimum)


def _encode_caa(record: CAARecord) -> bytes:
    tag = record.tag.encode("ascii")
    value = record.value.encode("ascii")
    return bytes([record.flags, len(tag)]) + tag + value


# ---------------------------------------------------------------------------
# RDATA decoders
# ---------------------------------------------------------------------------

def _decode_a(data: bytes, offset: int, rdlength: int) -> ARecord:
    return ARecord(inet_ntoa(data[offset: offset + 4]))


def _decode_aaaa(data: bytes, offset: int, rdlength: int) -> AAAARecord:
    return AAAARecord(inet_ntop(AF_INET6, data[offset: offset + 16]))


def _decode_name_only(cls, data: bytes, offset: int, rdlength: int):
    name, _ = decode_name(data, offset)
    return cls(name)


def _decode_mx(data: bytes, offset: int, rdlength: int) -> MXRecord:
    pref = unpack(">H", data[offset: offset + 2])[0]
    exchange, _ = decode_name(data, offset + 2)
    return MXRecord(pref, exchange)


def _decode_txt(data: bytes, offset: int, rdlength: int) -> TXTRecord:
    strings = []
    end = offset + rdlength
    pos = offset
    while pos < end:
        slen = data[pos]
        pos += 1
        strings.append(data[pos: pos + slen])
        pos += slen
    return TXTRecord(strings)


def _decode_srv(data: bytes, offset: int, rdlength: int) -> SRVRecord:
    priority, weight, port = unpack(">HHH", data[offset: offset + 6])
    target, _ = decode_name(data, offset + 6)
    return SRVRecord(priority, weight, port, target)


def _decode_soa(data: bytes, offset: int, rdlength: int) -> SOARecord:
    mname, pos = decode_name(data, offset)
    rname, pos = decode_name(data, pos)
    serial, refresh, retry, expire, minimum = unpack(">IIIII", data[pos: pos + 20])
    return SOARecord(mname, rname, serial, refresh, retry, expire, minimum)


def _decode_caa(data: bytes, offset: int, rdlength: int) -> CAARecord:
    flags = data[offset]
    tag_len = data[offset + 1]
    tag = data[offset + 2: offset + 2 + tag_len].decode("ascii")
    value = data[offset + 2 + tag_len: offset + rdlength].decode("ascii")
    return CAARecord(flags, tag, value)


# ---------------------------------------------------------------------------
# Main codec
# ---------------------------------------------------------------------------

class DNSCodec:
    """
    Encodes and decodes DNS messages to/from wire format.
    Completely transport-agnostic.
    """

    _DECODERS = {
        RecordType.A:     _decode_a,
        RecordType.AAAA:  _decode_aaaa,
        RecordType.CNAME: lambda d, o, l: _decode_name_only(CNAMERecord, d, o, l),
        RecordType.NS:    lambda d, o, l: _decode_name_only(NSRecord, d, o, l),
        RecordType.PTR:   lambda d, o, l: _decode_name_only(PTRRecord, d, o, l),
        RecordType.MX:    _decode_mx,
        RecordType.TXT:   _decode_txt,
        RecordType.SRV:   _decode_srv,
        RecordType.SOA:   _decode_soa,
        RecordType.CAA:   _decode_caa,
    }

    # ---------------------------------------------------------------------------
    # Encoding
    # ---------------------------------------------------------------------------

    def encode(self, message: DNSMessage) -> bytes:
        """
        Encode a complete DNS message to wire-format bytes.
        """

        compression: Dict[str, int] = {}

        body = bytearray()
        base = DNSHeader.SIZE

        for q in message.questions:
            name_bytes = encode_name(q.name, compression, base + len(body))
            body += name_bytes + pack(">HH", q.qtype, q.qclass)

        for rr in (message.answers + message.authorities + message.additionals):
            body += self._encode_rr(rr, compression, base + len(body))

        hdr = message.header
        hdr.question_count   = len(message.questions)
        hdr.answer_count     = len(message.answers)
        hdr.authority_count  = len(message.authorities)
        hdr.additional_count = len(message.additionals)

        return hdr.pack() + bytes(body)

    def _encode_rr(self, rr: DNSResourceRecord,
                   compression: Dict[str, int], offset: int) -> bytes:
        name_bytes = encode_name(rr.name, compression, offset)
        offset_after_name = offset + len(name_bytes)
        # type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes before rdata
        rdata_offset = offset_after_name + 10

        rdata = self._encode_rdata(rr.rtype, rr.rdata, compression, rdata_offset)
        header = pack(">HHI", rr.rtype, rr.rclass, rr.ttl)
        return name_bytes + header + pack(">H", len(rdata)) + rdata

    def _encode_rdata(self, rtype: int, rdata, compression, offset: int) -> bytes:
        if rdata is None:
            return b""
        if isinstance(rdata, bytes):
            return rdata
        if isinstance(rdata, ARecord):
            return _encode_a(rdata)
        if isinstance(rdata, AAAARecord):
            return _encode_aaaa(rdata)
        if isinstance(rdata, (CNAMERecord, NSRecord, PTRRecord)):
            name = (rdata.target if hasattr(rdata, "target")
                    else rdata.nameserver if hasattr(rdata, "nameserver")
                    else rdata.ptrdname)
            return _encode_name_only(name, compression, offset)
        if isinstance(rdata, MXRecord):
            return _encode_mx(rdata, compression, offset)
        if isinstance(rdata, TXTRecord):
            return _encode_txt(rdata)
        if isinstance(rdata, SRVRecord):
            return _encode_srv(rdata, compression, offset)
        if isinstance(rdata, SOARecord):
            return _encode_soa(rdata, compression, offset)
        if isinstance(rdata, CAARecord):
            return _encode_caa(rdata)
        raise TypeError(f"Cannot encode rdata of type {type(rdata)}")

    # ---------------------------------------------------------------------------
    # Decoding
    # ---------------------------------------------------------------------------

    def decode(self, data: bytes) -> DNSMessage:
        """
        Decode wire-format bytes into a DNSMessage.
        """

        if len(data) < DNSHeader.SIZE:
            raise ValueError("DNS message too short")

        header = DNSHeader.unpack(data)
        offset = DNSHeader.SIZE
        msg = DNSMessage(header=header)

        for _ in range(header.question_count):
            name, offset = decode_name(data, offset)
            qtype, qclass = unpack(">HH", data[offset: offset + 4])
            offset += 4
            msg.questions.append(DNSQuestion(name, qtype, qclass))

        msg.answers, offset     = self._decode_rr_section(data, offset, header.answer_count)
        msg.authorities, offset = self._decode_rr_section(data, offset, header.authority_count)
        msg.additionals, offset = self._decode_rr_section(data, offset, header.additional_count)

        return msg

    def _decode_rr_section(
        self, data: bytes, offset: int, count: int
    ) -> Tuple[List[DNSResourceRecord], int]:
        records = []
        for _ in range(count):
            rr, offset = self._decode_rr(data, offset)
            records.append(rr)
        return records, offset

    def _decode_rr(self, data: bytes, offset: int) -> Tuple[DNSResourceRecord, int]:
        name, offset = decode_name(data, offset)
        rtype, rclass, ttl, rdlength = unpack(">HHIH", data[offset: offset + 10])
        offset += 10
        rdata_raw = data[offset: offset + rdlength]

        decoder = self._DECODERS.get(rtype)
        if decoder:
            try:
                rdata = decoder(data, offset, rdlength)
            except Exception:
                rdata = rdata_raw
        else:
            rdata = rdata_raw

        offset += rdlength
        return DNSResourceRecord(name, rtype, rclass, ttl, rdata), offset

codec = DNSCodec()
