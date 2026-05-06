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
This package implements a basic asynchronous DNS client and server
with a feature to exfiltrate data through DNS.
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
    "encode_name",
    "decode_name",
    "DNSCodec",
    "codec",
    "Zone",
    "DNSRequestHandler",
    "DNSServer",
    "start_dns_server",
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
    "ExfiltratorFile",
    "exfiltrator_resolver",
    "start_exfiltrator_server",
    "process_chunks",
    "read_and_chunk_file",
    "process_directory",
    "process_directories",
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

if __package__:
    from .datatypes import (
        RecordType,
        RecordClass,
        Opcode,
        ResponseCode,
        DNSFlags,
        DNSHeader,
        DNSQuestion,
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
        DNSResourceRecord,
        DNSMessage,
    )
    from .codec import (
        encode_name,
        decode_name,
        DNSCodec,
        codec,
    )
    from .server import (Zone, DNSRequestHandler, DNSServer, start_dns_server)
    from .client import (
        send_udp_raw,
        send_tcp_raw,
        build_query,
        query,
        query_udp,
        query_tcp,
        resolve_a,
        resolve_aaaa,
        resolve_cname,
        resolve_mx,
        resolve_ns,
        resolve_txt,
        resolve_srv,
        resolve_ptr,
        resolve_soa,
        resolve_caa,
        resolve_any,
        resolve,
    )
    from .exfiltrator_server import (
        ExfiltratorFile,
        exfiltrator_resolver,
        start_exfiltrator_server,
    )
    from .exfiltrator_client import (
        process_chunks,
        read_and_chunk_file,
        process_directory,
        process_directories,
    )
    from .__main__ import main
else:
    from datatypes import (
        RecordType,
        RecordClass,
        Opcode,
        ResponseCode,
        DNSFlags,
        DNSHeader,
        DNSQuestion,
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
        DNSResourceRecord,
        DNSMessage,
    )
    from codec import (
        encode_name,
        decode_name,
        DNSCodec,
        codec,
    )
    from server import (Zone, DNSRequestHandler, DNSServer, start_dns_server)
    from client import (
        send_udp_raw,
        send_tcp_raw,
        build_query,
        query,
        query_udp,
        query_tcp,
        resolve_a,
        resolve_aaaa,
        resolve_cname,
        resolve_mx,
        resolve_ns,
        resolve_txt,
        resolve_srv,
        resolve_ptr,
        resolve_soa,
        resolve_caa,
        resolve_any,
        resolve,
    )
    from exfiltrator_server import (
        ExfiltratorFile,
        exfiltrator_resolver,
        start_exfiltrator_server,
    )
    from exfiltrator_client import (
        process_chunks,
        read_and_chunk_file,
        process_directory,
        process_directories,
    )
    from __main__ import main
