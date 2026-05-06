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
DNS types, constants, and RFC-compliant data structures.
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
    "RecordType",
    "RecordClass",
    "Opcode",
    "ResponseCode",
    "DNSFlags",
    "DNSHeader",
    "DNSQuestion",
    "ARecord",
    "AAAARecord",
    "CNAMERecord",
    "NSRecord",
    "PTRRecord",
    "MXRecord",
    "TXTRecord",
    "SRVRecord",
    "SOARecord",
    "CAARecord",
    "DNSResourceRecord",
    "DNSMessage",
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

from enum import IntEnum
from struct import pack, unpack
from dataclasses import dataclass, field
from typing import List, Optional, Union, Any


# ---------------------------------------------------------------------------
# DNS Record Types (RFC 1035, 1886, 2782, 2915, 3596, 4034, etc.)
# ---------------------------------------------------------------------------

class RecordType(IntEnum):
    """
    Enumeration of DNS record types as defined in multiple RFCs.
    """

    A     = 1      # IPv4 address
    NS    = 2      # Authoritative name server
    CNAME = 5      # Canonical name alias
    SOA   = 6      # Start of authority
    PTR   = 12     # Domain name pointer (reverse lookup)
    MX    = 15     # Mail exchange
    TXT   = 16     # Text record
    AAAA  = 28     # IPv6 address
    SRV   = 33     # Service locator
    CAA   = 257    # Certification Authority Authorization
    ANY   = 255    # Any/all record types


class RecordClass(IntEnum):
    """
    Enumeration of DNS record classes.
    """

    IN  = 1    # Internet
    ANY = 255  # Any class


class Opcode(IntEnum):
    """
    Enumeration of DNS operation codes.
    """

    QUERY  = 0
    IQUERY = 1
    STATUS = 2


class ResponseCode(IntEnum):
    """
    Enumeration of DNS response codes returned in replies.
    """

    NOERROR  = 0   # No error
    FORMERR  = 1   # Format error
    SERVFAIL = 2   # Server failure
    NXDOMAIN = 3   # Non-existent domain
    NOTIMP   = 4   # Not implemented
    REFUSED  = 5   # Query refused


# ---------------------------------------------------------------------------
# DNS Header (RFC 1035 §4.1.1)
# ---------------------------------------------------------------------------

@dataclass
class DNSFlags:
    """
    Represents DNS header flags and provides serialization utilities.
    """

    qr: int = 0          # 0 = query, 1 = response
    opcode: int = 0      # Opcode (4 bits)
    aa: int = 0          # Authoritative answer
    tc: int = 0          # Truncated
    rd: int = 1          # Recursion desired
    ra: int = 0          # Recursion available
    z: int = 0           # Reserved (must be 0)
    rcode: int = 0       # Response code (4 bits)

    def to_int(self) -> int:
        """
        Serialize the DNS flags into a 16-bit integer according to RFC 1035.
        """

        return (
            (self.qr    & 0x1) << 15 |
            (self.opcode & 0xF) << 11 |
            (self.aa    & 0x1) << 10 |
            (self.tc    & 0x1) <<  9 |
            (self.rd    & 0x1) <<  8 |
            (self.ra    & 0x1) <<  7 |
            (self.z     & 0x7) <<  4 |
            (self.rcode & 0xF)
        )

    @classmethod
    def from_int(cls, value: int) -> "DNSFlags":
        """
        Deserialize a 16-bit integer into a DNSFlags instance.
        """

        return cls(
            qr     = (value >> 15) & 0x1,
            opcode = (value >> 11) & 0xF,
            aa     = (value >> 10) & 0x1,
            tc     = (value >>  9) & 0x1,
            rd     = (value >>  8) & 0x1,
            ra     = (value >>  7) & 0x1,
            z      = (value >>  4) & 0x7,
            rcode  = (value      ) & 0xF,
        )


@dataclass
class DNSHeader:
    """
    Represents the DNS message header structure (12 bytes).
    """

    transaction_id: int = 0
    flags: DNSFlags = field(default_factory=DNSFlags)
    question_count: int = 0
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0

    SIZE = 12

    def pack(self) -> bytes:
        """
        Pack the DNS header into its binary representation.
        """

        return pack(
            ">HHHHHH",
            self.transaction_id,
            self.flags.to_int(),
            self.question_count,
            self.answer_count,
            self.authority_count,
            self.additional_count,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "DNSHeader":
        """
        Unpack raw bytes into a DNSHeader instance.
        """

        tid, flags, qc, ac, auth, add = unpack(">HHHHHH", data[:12])
        return cls(
            transaction_id=tid,
            flags=DNSFlags.from_int(flags),
            question_count=qc,
            answer_count=ac,
            authority_count=auth,
            additional_count=add,
        )


# ---------------------------------------------------------------------------
# DNS Question
# ---------------------------------------------------------------------------

@dataclass
class DNSQuestion:
    """
    Represents a DNS question section entry.
    """

    name: str
    qtype: int = RecordType.A
    qclass: int = RecordClass.IN


# ---------------------------------------------------------------------------
# DNS Resource Record data classes
# ---------------------------------------------------------------------------

@dataclass
class ARecord:
    """
    Represents an IPv4 address (A record).
    """

    address: str  # "1.2.3.4"


@dataclass
class AAAARecord:
    """
    Represents an IPv6 address (AAAA record).
    """

    address: str  # "2001:db8::1"


@dataclass
class CNAMERecord:
    """
    Represents a canonical name (alias) record.
    """

    target: str


@dataclass
class NSRecord:
    """
    Represents an authoritative name server record.
    """

    nameserver: str


@dataclass
class PTRRecord:
    """
    Represents a reverse DNS pointer record.
    """

    ptrdname: str


@dataclass
class MXRecord:
    """
    Represents a mail exchange record with priority.
    """

    preference: int
    exchange: str


@dataclass
class TXTRecord:
    """
    Represents a text record containing one or more byte strings.
    """

    strings: List[bytes]  # list of byte strings (each up to 255 bytes)


@dataclass
class SRVRecord:
    """
    Represents a service locator record.
    """

    priority: int
    weight: int
    port: int
    target: str


@dataclass
class SOARecord:
    """
    Represents the Start of Authority record.
    """

    mname: str      # Primary nameserver
    rname: str      # Responsible mailbox
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


@dataclass
class CAARecord:
    """
    Represents a Certification Authority Authorization record.
    """

    flags: int      # 0 or 128 (issuer critical)
    tag: str        # "issue", "issuewild", "iodef"
    value: str


# Union type for all RDATA
RData = Union[
    ARecord, AAAARecord, CNAMERecord, NSRecord, PTRRecord,
    MXRecord, TXTRecord, SRVRecord, SOARecord, CAARecord, bytes
]


@dataclass
class DNSResourceRecord:
    """
    Represents a generic DNS resource record.
    """

    name: str
    rtype: int
    rclass: int = RecordClass.IN
    ttl: int = 300
    rdata: Optional[RData] = None


@dataclass
class DNSMessage:
    """
    Represents a full DNS message including all sections.
    """

    header: DNSHeader = field(default_factory=DNSHeader)
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSResourceRecord] = field(default_factory=list)
    authorities: List[DNSResourceRecord] = field(default_factory=list)
    additionals: List[DNSResourceRecord] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        """
        Return True if this message is a DNS response.
        """

        return self.header.flags.qr == 1

    @property
    def is_query(self) -> bool:
        """
        Return True if this message is a DNS query.
        """

        return self.header.flags.qr == 0
