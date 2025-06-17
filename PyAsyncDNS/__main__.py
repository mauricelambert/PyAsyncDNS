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

__version__ = "0.0.3"
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

print(copyright)

if __package__:
    from . import server
    from .server import main as server
    from .client import main as client
    from .exfiltrator import main as exfiltration
    from .exfiltrator_server import get_response as get_exfiltration
else:
    from client import main as client
    from server import main as server
    from exfiltrator import main as exfiltration
    from exfiltrator_server import get_response as get_exfiltration
    import server

from sys import exit, argv, executable, stderr

if len(argv) >= 2:
    command = argv.pop(1)
    if command.casefold() == "client":
        exit(client())
    elif command.casefold() == "server":
        exit(server())
    elif command.casefold() == "exfiltration":
        exit(exfiltration())
    elif command.casefold() == "exfiltration-server":
        server.get_response = get_exfiltration
        exit(server())

print(
    "USAGES:",
    executable,
    "" if executable.endswith(argv[0]) else argv[0],
    "(client|server|exfiltration|exfiltration-server) ...",
    file=stderr,
)
exit(1)
