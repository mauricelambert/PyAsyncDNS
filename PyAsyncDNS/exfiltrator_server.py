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
DNS exfiltration server.

Receives base64-encoded file chunks via DNS queries and reconstructs files.
Replaces the old server.py-based approach; uses the new dns_server module.
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
    "ExfiltratorFile",
    "exfiltrator_resolver",
    "start_exfiltrator_server",
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

from sys import argv, stderr, exit, executable
from os import getcwd, makedirs
from os.path import join, dirname
from base64 import urlsafe_b64decode
from asyncio import run

if __package__:
    from .datatypes import (
        DNSMessage,
        DNSResourceRecord,
        RecordType,
        RecordClass,
        ResponseCode,
        DNSHeader,
        DNSFlags,
        ARecord,
    )
    from .server import DNSServer, Zone
    from .codec import codec
else:
    from datatypes import (
        DNSMessage,
        DNSResourceRecord,
        RecordType,
        RecordClass,
        ResponseCode,
        DNSHeader,
        DNSFlags,
        ARecord,
    )
    from server import DNSServer, Zone
    from codec import codec


EXFIL_IP = "127.0.0.1"
prefix = getcwd()


class ExfiltratorFile:
    """
    Tracks an in-progress exfiltrated file.
    """

    def __init__(self, first_label: str, transaction_id: int):
        self.id = transaction_id
        self.length = 0
        data = [urlsafe_b64decode(x).decode() for x in first_label.split(".")]
        self.size = int(data[-1])
        full_path = join(prefix, *data[:-1])
        makedirs(dirname(full_path), exist_ok=True)
        self.file = open(full_path, "wb")

    def write_batch(self, domain: str) -> None:
        """
        This method writes file content by batchs and chunks. 
        """

        for chunk in domain.split("."):
            raw = urlsafe_b64decode(chunk.encode())
            self.file.write(raw)
            self.length += len(raw)
        if self.length >= self.size:
            self.file.close()
            del active_files[self.id]


active_files: dict = {}


def exfiltrator_resolver(query_msg: DNSMessage):
    """
    Custom resolver that reassembles exfiltrated files from DNS queries.
    """

    if not query_msg.questions:
        return None

    q = query_msg.questions[0]
    tid = query_msg.header.transaction_id

    f = active_files.get(tid)
    if f is None:
        try:
            active_files[tid] = ExfiltratorFile(q.name, tid)
        except Exception as e:
            print(f"[exfil] Invalid first packet: {e}", file=stderr)
    else:
        try:
            f.write_batch(q.name)
        except Exception as e:
            print(f"[exfil] Write error: {e}", file=stderr)

    answers = [DNSResourceRecord(
        name=q.name,
        rtype=RecordType.A,
        rclass=RecordClass.IN,
        ttl=0,
        rdata=ARecord(EXFIL_IP),
    )]

    response = DNSMessage(
        header=DNSHeader(
            transaction_id=tid,
            flags=DNSFlags(qr=1, rd=query_msg.header.flags.rd, ra=1),
            question_count=1,
            answer_count=1,
        ),
        questions=query_msg.questions,
        answers=answers,
    )
    return response


async def start_exfiltrator_server(host: str, port: int) -> None:
    """
    This function starts the exfiltration server.
    """

    server = DNSServer(resolver=exfiltrator_resolver, host=host, port=port)
    print(f"[exfil] DNS exfiltration server on {host}:{port}")
    await server.serve_forever()


def main() -> int:
    """
    The main function to run the exfiltration
    server from the command line.
    """

    print(__copyright__)

    if len(argv) != 3:
        print(f"Usage: {executable} {argv[0]} <host> <port>", file=stderr)
        return 1
    if not argv[2].isdigit():
        print("Error: port must be an integer.", file=stderr)
        return 1
    try:
        run(start_exfiltrator_server(argv[1], int(argv[2])))
        return 0
    except KeyboardInterrupt:
        print("\n[exfil] Server stopped.")
        return 0


if __name__ == "__main__":
    exit(main())
