![](https://github.com/leap-protocol/leap-py/workflows/L3aP-Py%20Testing/badge.svg)
# L3aP for Python
Legible encoding for addressable packets for python

Specification documentation:
https://leap-protocol.github.io/

# Installation

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
received, packet = codec.Decode(received)
data = codec.unpack(packet)

for branch, value in data.items():
  ... do stuff ...

...
```

# Usage

## Codec Class

### codec = Codec(config_file_path)
* **config_file_path** a string to point to the L3aP config file.
* **codec** L3aP codec object

Instantiates a L3aP codec object for encoding packets to strings and decoding strings to packets.

Example:
``` python
codec = leap.Codec("leap-config.json")
```

### bytes = encode(packets)
* **packets** either a `leap.Packet` object or a list of `leap.packet` objects.
* **bytes** utf-8 byte string

Encodes one or more packets into a utf-8 byte string.

Example:
```python
packet_red = leap.Packet("set", "led/red", True)
packet_blue = leap.Packet("set", "led/blue", True)

encoded = codec.encode([packet_red, packet_blue])
```

### (remainder, packets) = decode(bytes)
* **bytes** utf-8 encoded byte-string
* **remainder** unused bytes (if available)
* **packets** an array of one or more decoded packets, empty if none

Decodes a utf-8 byte string into one or more packets

Example:
```python
received_bytes += rx.read()
received_bytes, packets = codec.decode(received_bytes)

for packet in packets:
  ...
```

### data = unpack(packet)
* **packet** a `leap.Packet`
* **data** a dictionary with address paths as keys (eg. `led/red`) mapping to thier respective values.

Extracts a dictionary from a packet to map address paths to thier respective values.

Example:
```python
if packet.category == "set":
  commands = codec.unpack(packet)
  if 'led/red' in commands:
    led_red.set(commands['led/red']
    ...
```

## Packet Class

### packet = Packet(category, *path*, *payload*)
* **category** the type of packet
* **path** (optional) a root path of payload data
* **payload** (optional) the data to accompany the root path
* **packet** a L3aP packet object

Constructs a L3aP packet for encoding. Note, payload can be an array and set multiple fields at once when the path is a parent.

Example:
```python
accelerometer_packet = leap.Packet("pub", "imu/accel", [accel_x, accel_y, accel_z])
disable_packet = leap.Packet("set", "control/balance/disable")
...
```

### add(path, *payload*)
* **path** a root path of payload data
* **payload** (optional) the data to accompany the root path

Adds path to the packet and optionally a payload.
This can be used to create compound packets which allows sets of data to be processed at the same time.

Example:
```python
sensor_packet = leap.Packet("pub", "imu/accel", [accel_x, accel_y, accel_z])
sensor_packet.add("barometer/pressure", baro_pressure)
...
```

### category

The packet's category string.

Example:
```python
if packet.category == "pub":
  update_model(codec.unpack(packet))
...
```

## Verification

### result = verify(config_file)
* **config_file** a valid L3aP config file
* **result** false if config_file is invalid, true otherwise

Checks the contents of a config_file for errors. Prints details of the first failure to stdout. Useful for regression testing.

Example:
```python
...
def test_valid_config(self):
  assert(leap.verify("leap-config.json"))
...
```

# Command Line

Generate a default json config file:

`python3 -m leap --json filename.toml`

Generate a default toml config file:

`python3 -m leap --toml filename.toml`

Verify the contents of your toml/json config file:

`python3 -m leap --validate filename.json`

Help:

`python3 -m leap --help`


