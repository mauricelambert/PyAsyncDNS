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

from asyncio import start_server, DatagramProtocol, get_event_loop, run
from socket import AF_INET, SOCK_DGRAM, socket
from sys import argv, exit, stderr, executable
from typing import Tuple, Optional, List
from struct import unpack, pack

if __package__:
    from .lib import (
        parse_dns_query,
        build_dns_response_packet,
        build_a_record_rdata,
    )
else:
    from lib import (
        parse_dns_query,
        build_dns_response_packet,
        build_a_record_rdata,
    )


def get_response(domain_name: str, transaction_id: int) -> str:
    """
    This function returns the IP address from domain name and transaction ID.

    You should replace this function with your own function.
    """

    return "127.0.0.1"


def handle_dns_request(request_data: bytes) -> Optional[bytes]:
    """
    Handle an incoming DNS query and build a response.

    Args:
        request_data: Raw DNS query packet bytes.

    Returns:
        Raw DNS response packet bytes or None if invalid query.
    """

    try:
        transaction_id, question_list = parse_dns_query(request_data)
    except Exception:
        return None

    answer_list: List[Tuple[str, int, int, int, bytes]] = []

    for domain_name, query_type, query_class in question_list:
        if query_type == 1 and query_class == 1:
            answer_data = build_a_record_rdata(
                get_response(domain_name, transaction_id)
            )
            answer_list.append(
                (domain_name, query_type, query_class, 300, answer_data)
            )

    return build_dns_response_packet(
        transaction_id, question_list, answer_list
    )


class DNSDatagramProtocol(DatagramProtocol):
    """
    Asynchronous DNS UDP protocol handler.
    """

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        response_data = handle_dns_request(data)
        if response_data:
            self.transport.sendto(response_data, addr)

    def connection_made(self, transport) -> None:
        self.transport = transport


async def handle_tcp_connection(reader, writer) -> None:
    """
    Handle an incoming TCP DNS connection.

    Args:
        reader: StreamReader for TCP connection.
        writer: StreamWriter for TCP connection.
    """

    try:
        length_prefix = await reader.readexactly(2)
        request_length = unpack(">H", length_prefix)[0]
        request_data = await reader.readexactly(request_length)

        response_data = handle_dns_request(request_data)
        if response_data:
            writer.write(pack(">H", len(response_data)) + response_data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def start_async_dns_server(
    host: str = "0.0.0.0", port: int = 5353
) -> None:
    """
    Start the asynchronous DNS server handling both UDP and TCP.

    Args:
        host: IP address to bind to.
        port: Port number to bind to.
    """

    loop = get_event_loop()

    print(f"DNS server listening on {host}:{port} (UDP/TCP)")

    transport, _ = await loop.create_datagram_endpoint(
        lambda: DNSDatagramProtocol(), local_addr=(host, port)
    )

    tcp_server = await start_server(handle_tcp_connection, host, port)

    async with tcp_server:
        await tcp_server.serve_forever()


def main() -> int:
    """
    Synchronous entry point for the DNS async server.

    Returns:
        Exit code.
    """

    print(copyright)

    if len(argv) != 3:
        print("Usage:", executable, argv[0], "host port", file=stderr)
        return 1

    host = argv[1]
    if argv[2].isdigit():
        port = int(argv[2])
    else:
        print("Error: port must be an integer.", file=stderr)
        return 1

    try:
        run(start_async_dns_server(host, port))
        return 0
    except KeyboardInterrupt:
        print("\nServer interrupted.")
        return 0
    except Exception as error:
        print(f"Server error: {error}")
        return 127


if __name__ == "__main__":
    exit(main())
