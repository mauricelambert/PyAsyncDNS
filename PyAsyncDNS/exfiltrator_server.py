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

from sys import stderr, exit
from os import getcwd, makedirs
from os.path import join, dirname
from base64 import urlsafe_b64decode

if __package__:
    from . import server
else:
    import server

prefix = getcwd()


class File:
    """
    This class implements a file to read and write the exfiltrate files.
    """

    def __init__(self, first: str, id: int):
        self.id = id
        self.length = 0
        data = [
            urlsafe_b64decode(x).decode() for x in first.encode().split(b".")
        ]
        self.size = int(data[-1])
        full_filename = join(prefix, *data[:-1])
        makedirs(dirname(full_filename), exist_ok=True)
        self.file = open(full_filename, "wb")

    def read(self, batch: bytes) -> None:
        """
        This method splits chunks from batch, decode and write it.
        """

        for chunk in batch.split("."):
            data = urlsafe_b64decode(chunk.encode())
            self.file.write(data)
            self.length += len(data)

        if self.length >= self.size:
            self.file.close()
            del files[self.id]


files = {}


def get_response(domain_name: str, transaction_id: int) -> str:
    """
    This function reads exfiltrate data.
    """

    file = files.get(transaction_id)

    if file is None:
        try:
            files[transaction_id] = file = File(domain_name, transaction_id)
        except Exception as e:
            print(f"Invalid first packet: {e}", file=stderr)
        return "127.0.0.1"

    try:
        file.read(domain_name)
    except Exception as e:
        print(f"Invalid data packet: {e}", file=stderr)

    return "127.0.0.1"


if __name__ == "__main__":
    server.get_response = get_response
    exit(server.main())
