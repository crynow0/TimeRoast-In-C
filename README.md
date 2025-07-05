# Timeroast — MS-SNTP (TimeRoast) Hash Extraction Tool

This script sends crafted SNTP requests to a Windows Domain Controller (DC) over UDP/123 and parses the MAC-style authenticator that the DC returns, yielding **Hashcat mode 31300** lines:

> ⚠️ **Ethical use only**  
> Run this code **exclusively** against systems you own or are authorized to test.


## Build

| Platform      | Command                                                                        |
|---------------|--------------------------------------------------------------------------------|
| Linux/macOS   | `gcc -Wall -O2 -o timeroast timeroast.c`                                       |
| Windows (x64) | `x86_64-w64-mingw32-gcc -O2 timeroast.c -o timeroast.exe -lws2_32`             |

## Usage

| Option | Argument      | Description                                                                  |
|--------|---------------|------------------------------------------------------------------------------|
| `-d`   | `<IP|FQDN>`   | **Domain Controller** to target (IPv4 or hostname) **(required)**            |
| `-r`   | `<list>`      | **RID(s)** – e.g. `500,1000-1200,2500` **(required)**                        |
| `-a`   | `<rate>`      | Requests per second (default **180**)                                        |
| `-t`   | `<sec>`       | Silence timeout — exit after _n_ seconds without new hashes (default **24**) |
| `-l`   | —             | Use **legacy** RID encoding (flip bit 31)                                    |
| `-p`   | `<port>`      | Source UDP port to bind (useful behind firewalls/NAT)                        |
| `-o`   | `<file>`      | Write hashes to file instead of `stdout`                                     |


### Usage example:
```bash
sudo ./timeroast -d <ip_addr> -r <numbers_range> -o hashes.txt
```
#### Acknowledgements
Thanks to Tom Tervoort for the original PoC and research.
