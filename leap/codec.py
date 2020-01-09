# RoBus Codec
# 2019 (C) Hoani Bryson

from . import packet
from .helpers import typeHelper, explore, protocolKey, itemData

import json, toml


class Codec():
  def __init__(self, protocol_file_path):
    try:
      with open(protocol_file_path, "r") as protocol_file:
        self._protocol = json.load(protocol_file)
      self._is_valid = True
    except:
      self._is_valid = False

    if self._is_valid == False:
      try:
        with open(protocol_file_path, "r") as protocol_file:
          self._protocol = toml.load(protocol_file)
        self._is_valid = True
      except:
        self._is_valid = False


    if self._is_valid:
      self._generate_maps(self._protocol)
      self._generate_category_map()


  def valid(self):
    return self._is_valid


  def encode(self, packets):
    if self._is_valid == False:
      return ""

    if isinstance(packets, packet.Packet):
      packets = [packets]
    elif not isinstance(packets, list):
      return ""

    encoded = ""
    for _packet in packets:
      if encoded != "":
        encoded += self._protocol["end"]

      encoded += self._protocol["category"][_packet.category]

      internal = ""

      paths_and_payloads = tuple(zip(_packet.paths, _packet.payloads))
      for (ppath, ppayload) in paths_and_payloads:
        if ppath != None:
          if internal != "":
            internal += self._protocol["compound"]

          path = ppath.split("/")
          root = explore.get_struct(self._protocol, [path[0]])

          if ppath in self.encode_map:
            encode_data = self.encode_map[ppath]
          else:
            print("invalid address: {}".format(ppath))
            return "".encode("utf-8")

          internal += encode_data.addr

          if ppayload != None:

            count = min(len(encode_data.types), len(ppayload))
            for i in range(count):
              internal += self._protocol["separator"]
              internal += typeHelper.encode_types(ppayload[i], encode_data.types[i])

      encoded += internal

    encoded += self._protocol["end"]
    return encoded.encode('utf-8')


  ## Decodes an incoming packet stream
  # Inputs: <byte-string> encoded
  # Returns: Tuple(<byte-string> remainder, Array[<packet>] Packets)
  #
  def decode(self, encoded):
    if self._is_valid == "false":
      return (encoded, [])

    strings = encoded.split(self._protocol["end"].encode('utf-8'))
    remainder = strings[-1]
    packets = []
    if len(strings) == 1:
      return (remainder, [])

    strings = strings[0:-1]
    for string in strings:
      string = string.decode('utf-8')
      category = None
      path = None
      start = string[0]
      category = self._category_from_start(start)
      _packet = packet.Packet(category)
      subpackets = string[1:].split(self._protocol["compound"])
      for subpacket in subpackets:
        parts = subpacket.split(self._protocol["separator"])
        if parts != ['']:
          payload = []
          addr = parts[0]
          decode_data = self.decode_map[addr]

          for (item, typeof) in tuple(zip(parts[1:], decode_data.types)):
            payload.append(typeHelper.decode_types(item, typeof))

          payload = tuple(payload)
          _packet.add(decode_data.path, payload)

      packets.append(_packet)

    return (remainder, packets)


  def unpack(self, _packet):
    result = {}
    for ppath, ppayload in tuple(zip(_packet.paths, _packet.payloads)) :

      unpack_data = self.encode_map[ppath]
      for (branch, value) in tuple(zip(unpack_data.data_branches, ppayload)):
        result[branch] = value
    return result

  def _category_from_start(self, start):
    if start in self._category_map.keys():
      return self._category_map[start]
    else:
      return None

  def _generate_category_map(self):
    self._category_map = {}
    for key in self._protocol["category"].keys():
      self._category_map[self._protocol["category"][key]] = key

  def _generate_maps(self, protocol):
    encode_map = {}
    decode_map = {}
    count = explore.count_to_path(protocol, None)
    # TODO Track address depth and addr
    addr_path = []
    addr = 0
    prev_depth = 0
    max_depth = -1
    branches = explore.extract_branches(protocol, [])
    roots = []
    for branch in branches:
      roots.append(explore.get_struct(protocol, branch.split('/')))

    for i in range(len(roots)):
      root = roots[i]
      branch = branches[i]
      depth = branch.count('/')

      if max_depth < depth:
        addr_path.append("")

      if protocolKey.ADDR in root:
        if depth == 0:
          addr_path[depth] = root[protocolKey.ADDR]
        else:
          int_addr = int(addr_path[depth-1], 16) + int(root[protocolKey.ADDR], 16)
          addr_path[depth] = "{:04x}".format(int_addr)
      else:
        if addr_path[0] == "":
          addr_path[0] = "0000"
        else:
          addr_path[depth] = "{:04x}".format(int(addr_path[prev_depth],16) + 1)

      prev_depth = depth
      max_depth = max(max_depth, depth)
      addr = addr_path[depth]


      data_branches = []
      ends = explore.extract_decendants(root, [])
      types = explore.extract_types(root, [])
      for end in ends:
        if end != "":
          data_branch = '/'.join([branch, end])
        else:
          data_branch = branch
        data_branches.append(data_branch)


      encode_map[branch] = itemData.ItemData(addr=addr, path=branch, data_branches=data_branches, types=types)
      decode_map[addr] = encode_map[branch]

    (self.encode_map, self.decode_map) = (encode_map, decode_map)


def benchmark_encode_ten_thousand_same_packet():
  codec = Codec('RoBus/_test/fake/protocol.json')
  p = packet.Packet("set", "control/manual", ("RT", 0.5, 0.5))

  enc = ""
  for i in range(1, 100000):
    enc = codec.encode(p)


def benchmark_decode_ten_thousand_same_packet():
  codec = Codec('RoBus/_test/fake/protocol.json')
  enc = b"s8002:01:60dc9cc9:60dc9cc9\n"

  p = None
  for i in range(1, 100000):
    p = codec.decode(enc)

def benchmark_decode_and_unpack_same_packet():
  codec = Codec('RoBus/_test/fake/protocol.json')
  enc = b"s8002:01:60dc9cc9:60dc9cc9\n"

  p = None
  for i in range(1, 100000):
    (rem, p) = codec.decode(enc)
    unp = codec.unpack(p[0])


def benchmark_encode_decode_ten_thousand_same_packet():
  codec = Codec('RoBus/_test/fake/protocol.json')
  enc = b"s8002:01:60dc9cc9:60dc9cc9\n"
  pac = packet.Packet("set", "control/manual", ("RT", 0.5, 0.5))

  p = None
  e = None
  for i in range(1, 100000):
    p = codec.decode(enc)
    e = codec.encode(pac)

def benchmark_load():
  codec = Codec('RoBus/_test/fake/protocol.json')

if __name__ == "__main__":
  import timeit

  tests = [
    ("Encoding 100,000 packets:", "benchmark_encode_ten_thousand_same_packet"),
    ("Decoding 100,000 packets:", "benchmark_decode_ten_thousand_same_packet"),
    ("Decoding and Unpacking 100000 packets:", "benchmark_decode_and_unpack_same_packet"),
    ("Encode and decoding a packet 100,000 times:", "benchmark_encode_decode_ten_thousand_same_packet")
  ]

  for (print_line, function_string) in tests:
    setup = "from __main__ import "+function_string
    print("({})".format(function_string))
    print(print_line)
    print("                     {:0.3f}us per packet".format(
    (timeit.timeit(function_string+"()", setup=setup, number=1))*10.0

  ))




