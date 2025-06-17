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

from asyncio import (
    run,
    gather,
    open_connection,
    get_event_loop,
    wait_for,
    TimeoutError as AsyncTimeoutError,
    DatagramProtocol,
    Future,
)
from socket import AF_INET, SOCK_DGRAM, SOCK_STREAM, socket
from sys import argv, stderr, exit, executable
from struct import pack, unpack
from typing import List, Tuple

if __package__:
    from .lib import build_dns_query_packet, DNSHeader, decode_domain_name
else:
    from lib import (
        build_dns_query_packet,
        DNSHeader,
        decode_domain_name,
    )


class DNSClientProtocol(DatagramProtocol):
    """
    Asyncio DatagramProtocol implementation for sending a DNS query and receiving a response.
    Used internally by the `send_dns_udp_query` function.
    """

    def __init__(self, query_packet: bytes, response_future: Future):
        """
        Initialize the DNS client protocol.

        Args:
            query_packet (bytes): The DNS query packet to send.
            response_future (Future): Future object used to deliver the response back to the caller.
        """

        self.query_packet = query_packet
        self.response_future = response_future
        self.transport = None

    def connection_made(self, transport):
        """
        Called when the connection is made.

        Sends the DNS query packet immediately after the connection is established.
        """

        self.transport = transport
        self.transport.sendto(self.query_packet)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """
        Called when a datagram is received.

        Args:
            data (bytes): The received DNS response.
            addr (Tuple[str, int]): The address of the sender.

        Sets the response data in the future and closes the transport.
        """

        if not self.response_future.done():
            self.response_future.set_result(data)
        self.transport.close()

    def error_received(self, exc: Exception):
        """
        Called when a send or receive error occurs.

        Args:
            exc (Exception): The error that occurred.

        Sets the exception in the future and closes the transport.
        """

        if not self.response_future.done():
            self.response_future.set_exception(exc)
        if self.transport:
            self.transport.close()

    def connection_lost(self, exc):
        """
        Called when the connection is lost or closed.

        Args:
            exc (Optional[Exception]): The reason for the closure, if any.

        Ensures any pending exception is raised if the connection closes unexpectedly.
        """

        if exc and not self.response_future.done():
            self.response_future.set_exception(exc)


def parse_dns_response(response_data: bytes) -> List[str]:
    """
    Parse DNS response to extract IPv4 addresses from A records.

    Args:
        response_data: Raw DNS response bytes.

    Returns:
        List of IPv4 addresses as strings.
    """

    dns_header = DNSHeader.from_buffer_copy(response_data[:12])
    offset = 12

    for _ in range(dns_header.question_count):
        _, offset = decode_domain_name(response_data, offset)
        offset += 4

    resolved_ip_addresses = []

    for _ in range(dns_header.answer_count):
        if response_data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while response_data[offset] != 0:
                offset += response_data[offset] + 1
            offset += 1

        record_type, _, _, data_length = unpack(
            ">HHIH", response_data[offset : offset + 10]
        )
        offset += 10

        rdata = response_data[offset : offset + data_length]
        offset += data_length

        if record_type == 1 and data_length == 4:
            ip_address = ".".join(str(byte) for byte in rdata)
            resolved_ip_addresses.append(ip_address)

    return resolved_ip_addresses


async def send_dns_udp_query(
    domain_name: str,
    dns_server_ip: str = "8.8.8.8",
    dns_server_port: int = 53,
    **kwargs,
) -> List[str]:
    """
    Send a DNS query using fully asynchronous UDP sockets.

    Args:
        domain_name (str): The domain name to resolve.
        dns_server_ip (str): The IP address of the DNS server.
        dns_server_port (int): The port number of the DNS server (default: 53).

    Returns:
        List[str]: A list of resolved IPv4 addresses.

    Raises:
        asyncio.TimeoutError: If no response is received within 2 seconds.
        Exception: For socket or protocol errors.
    """

    query_packet: bytes = build_dns_query_packet(domain_name, **kwargs)

    loop = get_event_loop()
    response_future: Future = loop.create_future()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: DNSClientProtocol(query_packet, response_future),
        remote_addr=(dns_server_ip, dns_server_port),
    )

    try:
        response_data: bytes = await wait_for(response_future, timeout=2.0)
    finally:
        transport.close()

    return parse_dns_response(response_data)


async def send_dns_tcp_query(
    domain_name: str, dns_server_ip: str = "8.8.8.8", dns_server_port: int = 53
) -> List[str]:
    """
    Send a DNS query using TCP.

    Args:
        domain_name: The domain name to resolve.
        dns_server_ip: The DNS server IP address.

    Returns:
        List of IPv4 addresses.

    Raises:
        TimeoutError if no response is received.
    """

    query_packet = build_dns_query_packet(domain_name)
    prefixed_query = pack(">H", len(query_packet)) + query_packet

    try:
        reader, writer = await wait_for(
            open_connection(dns_server_ip, dns_server_port), timeout=3
        )
    except AsyncTimeoutError:
        raise TimeoutError("TCP connection timeout")

    writer.write(prefixed_query)
    await writer.drain()

    length_prefix = await reader.readexactly(2)
    response_length = unpack(">H", length_prefix)[0]
    response_data = await reader.readexactly(response_length)

    writer.close()
    await writer.wait_closed()

    return parse_dns_response(response_data)


async def resolve_domain(
    domain_name: str, dns_server_ip: str = "8.8.8.8", dns_server_port: int = 53
) -> Tuple[str, List[str] or str]:
    """
    Resolve a single domain asynchronously.

    Args:
        domain_name: The domain name to resolve.
        dns_server_ip: DNS server IP address.

    Returns:
        Tuple of domain name and list of IPs or error message.
    """

    try:
        if len(build_dns_query_packet(domain_name)) <= 512:
            return domain_name, await send_dns_udp_query(
                domain_name, dns_server_ip, dns_server_port
            )
        return domain_name, await send_dns_tcp_query(
            domain_name, dns_server_ip, dns_server_port
        )
    except TimeoutError as timeout_error:
        return domain_name, f"Timeout: {timeout_error}"
    except Exception as exception_error:
        return domain_name, f"Error: {exception_error}"


async def resolve_all(
    domain_names: List[str], **kwargs
) -> List[Tuple[str, List[str] or str]]:
    """
    Resolve all domain names concurrently.

    Args:
        domain_names: List of domain names.

    Returns:
        List of tuples containing domain and result.
    """

    return await gather(
        *(
            resolve_domain(domain_name, **kwargs)
            for domain_name in domain_names
        )
    )


def main() -> int:
    """
    Main function to parse arguments and run DNS resolution.

    Returns:
        Exit code: 0 on success, 1 on usage error, 2 on DNS resolution failure.
    """

    print(copyright)

    if len(argv) < 2:
        print(
            "Usage:",
            executable,
            argv[0],
            "<domain1> [domain2 ...]",
            file=stderr,
        )
        return 1

    domain_names = argv[1:]
    results = run(resolve_all(domain_names))

    had_error = False
    for domain_name, result in results:
        if isinstance(result, list):
            print(f"{domain_name}: {' '.join(result)}")
        else:
            print(f"{domain_name}: {result}", file=stderr)
            had_error = True

    return 2 if had_error else 0


if __name__ == "__main__":
    exit(main())
