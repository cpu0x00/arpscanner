# arpscanner
Asset Discovery using Address Resolution Protocol (ARP)

```
# arpscanner.py -h
usage: arpscanner.py [-h] [--spoof SPOOF] [--tries TRIES] target

positional arguments:
  target                the target network subnet for asset discovery [EX: 10.10.10.0/24]

options:
  -h, --help            show this help message and exit
  --spoof SPOOF, -s SPOOF
                        an ipv4 address to spoof the connections with
  --tries TRIES, -r TRIES
                        how many time to re-scan (the higher the more reliable) default=2

asset discovery using ARP
```
