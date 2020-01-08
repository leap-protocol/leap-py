# L3aP for Python
Legible encoding for addressable packets for python

![](https://github.com/leap-protocol/leap-py/workflows/L3aP%20Unit%20Testing/badge.svg)

Specification documentation: 
https://leap-protocol.github.io/

# Installation

TODO 
`pip install leap-protocol`

# Basic Usage

Encoding a packet:
``` python
import leap-protocol as leap

codec = leap.Codec("leap-config.json")

packet = leap.Packet("set", "led/red", True)

encoded = codec.encode(packet)

...
```

Decoding a packet
``` python
import leap-protocol as leap

codec = leap.Codec("leap-config.json")

...

# Note, if there is a remainder it will be stored back in bytes
bytes, packet = codec.Decode(bytes) 

data = codec.unpack(packet)

for branch, value in data.items():
  ... do stuff ...
  
...
```

# Usage

## Codec Class

**codec = Codec(config_file_path)**
* *config_file_path* a string to point to the L3aP config file.
* *codec* L3aP codec object

Instantiates a L3aP codec object for encoding packets to strings and decoding strings to packets.

Example:
``` python
codec = leap.Codec("leap-config.json")
```

**bytes = encode(packets)**
* *packets* either a `leap.Packet` object or a list of `leap.packet` objects.
* *bytes* utf-8 byte string

Encodes one or more packets into a utf-8 byte string.

Example:
```python
packet_red = leap.Packet("set", "led/red", True)
packet_blue = leap.Packet("set", "led/blue", True)

encoded = codec.encode([packet_red, packet_blue])
```

**(remainder, packets) = decode(bytes)**
* *bytes* utf-8 encoded byte-string
* *remainder* unused bytes (if available)
* *packets* an array of one or more decoded packets, empty if none

Decodes a utf-8 byte string into one or more packets

Example:
```python
received_bytes += rx.read()
received_bytes, packets = codec.decode(received_bytes)

for packet in packets:
  ...
```

## Packet Class


## Verification


## Generator

