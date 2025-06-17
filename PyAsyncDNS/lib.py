#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements a basic asynchronous DNS client and server
#    with a feature to exfiltrate data through DNS.
#    Copyright (C) 2025  PyAsyncDNS

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
This package implements a basic asynchronous DNS client and server
with a feature to exfiltrate data through DNS.
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This package implements a basic asynchronous DNS client and server
with a feature to exfiltrate data through DNS.
"""
__url__ = "https://github.com/mauricelambert/PyAsyncDNS"

# __all__ = []

__license__ = "GPL-3.0 License"
__copyright__ = """
PyAsyncDNS  Copyright (C) 2025  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
copyright = __copyright__
license = __license__

from ctypes import BigEndianStructure, c_ushort
from typing import List, Tuple, Optional
from struct import pack, unpack
from random import randint


class DNSHeader(BigEndianStructure):
    """
    DNS packet header structure for parsing and building.

    Fields correspond to DNS header fields as per RFC 1035.
    """

    _pack_ = 1
    _fields_ = [
        ("transaction_id", c_ushort),
        ("flags", c_ushort),
        ("question_count", c_ushort),
        ("answer_count", c_ushort),
        ("authority_record_count", c_ushort),
        ("additional_record_count", c_ushort),
    ]


def encode_domain_name(domain_name: str) -> bytes:
    """
    Encode a domain name into DNS message format.

    Args:
        domain_name: Domain name string (e.g. "example.com").

    Returns:
        Encoded domain name in DNS label format ending with null byte.
    """

    parts = domain_name.split(".")
    encoded = b""
    for label in parts:
        encoded += pack("B", len(label)) + label.encode("ascii")
    return encoded + b"\x00"


def decode_domain_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode a domain name from DNS message format, supporting compression.

    Args:
        data: Full DNS message bytes.
        offset: Offset in the data to start decoding from.

    Returns:
        A tuple with:
        - Decoded domain name string.
        - Offset just after the domain name.
    """

    labels = []
    initial_offset = offset
    jumped = False

    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            pointer_bytes = data[offset : offset + 2]
            pointer_offset = ((length & 0x3F) << 8) | pointer_bytes[1]
            if not jumped:
                initial_offset = offset + 2
            offset = pointer_offset
            jumped = True
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii"))
        offset += length

    domain_name = ".".join(labels)
    return domain_name, (initial_offset if jumped else offset)


def build_dns_query_packet(
    domain_name: str, transaction_id: int = None
) -> bytes:
    """
    Build a DNS query packet for A record of given domain.

    Args:
        domain_name: Domain to query.
        transaction_id: Optional transaction ID for the DNS header.

    Returns:
        Byte string of DNS query packet.
    """

    dns_header = DNSHeader()
    dns_header.transaction_id = (
        randint(0x0000, 0xFFFF) if transaction_id is None else transaction_id
    )
    dns_header.flags = 0x0100
    dns_header.question_count = 1
    dns_header.answer_count = 0
    dns_header.authority_record_count = 0
    dns_header.additional_record_count = 0

    encoded_domain = encode_domain_name(domain_name)
    query_type = 1
    query_class = 1
    question_section = encoded_domain + pack(">HH", query_type, query_class)

    return bytes(dns_header) + question_section


def parse_dns_query(data: bytes) -> Tuple[int, List[Tuple[str, int, int]]]:
    """
    Parse a DNS query packet extracting transaction id and questions.

    Args:
        data: Raw DNS message bytes.

    Returns:
        A tuple with:
        - Transaction ID
        - List of questions as tuples: (domain_name, query_type, query_class)
    """

    dns_header = DNSHeader.from_buffer_copy(data[:12])
    offset = 12
    questions = []

    for _ in range(dns_header.question_count):
        domain_name, offset = decode_domain_name(data, offset)
        query_type, query_class = unpack(">HH", data[offset : offset + 4])
        offset += 4
        questions.append((domain_name, query_type, query_class))

    return dns_header.transaction_id, questions


def build_dns_response_packet(
    transaction_id: int,
    questions: List[Tuple[str, int, int]],
    answers: List[Tuple[str, int, int, int, bytes]],
) -> bytes:
    """
    Build a DNS response packet with given answers.

    Args:
        transaction_id: Transaction ID to match query.
        questions: List of question tuples (domain_name, qtype, qclass).
        answers: List of answer tuples (name, type, class, ttl, rdata).

    Returns:
        Byte string of DNS response packet.
    """

    dns_header = DNSHeader()
    dns_header.transaction_id = transaction_id
    dns_header.flags = 0x8180
    dns_header.question_count = len(questions)
    dns_header.answer_count = len(answers)
    dns_header.authority_record_count = 0
    dns_header.additional_record_count = 0

    packet = bytes(dns_header)
    for domain_name, query_type, query_class in questions:
        packet += encode_domain_name(domain_name)
        packet += pack(">HH", query_type, query_class)

    for answer_name, answer_type, answer_class, ttl, rdata in answers:
        packet += encode_domain_name(answer_name)
        packet += pack(">HHI", answer_type, answer_class, ttl)
        packet += pack(">H", len(rdata))
        packet += rdata

    return packet


def build_a_record_rdata(ipv4_address: str) -> bytes:
    """
    Convert IPv4 address string to DNS A record RDATA.

    Args:
        ipv4_address: IPv4 address in dotted decimal form.

    Returns:
        4-byte binary representation of the IPv4 address.
    """

    return b"".join(pack("B", int(octet)) for octet in ipv4_address.split("."))


def build_txt_record_rdata(text: str) -> bytes:
    """
    Build TXT record RDATA from text string.

    Args:
        text: Text to store in TXT record.

    Returns:
        Byte string in DNS TXT format.
    """

    encoded_text = text.encode("utf-8")
    length = len(encoded_text)
    return pack("B", length) + encoded_text
