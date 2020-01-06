# RoBus Codec
# 2019 (C) Hoani Bryson

from . import packet

import json, struct


class ItemData:
  def __init__(self, path = "", addr = "0000", data_branches=[], types=[]):
    self.addr = addr
    self.path = path
    self.data_branches = data_branches
    self.types = types

class protocolKey:
  TYPE = "type"
  ADDR = "addr"
  DATA = "data"

def count_depth(root):
  count = 0

  if protocolKey.DATA in root:
    data = root[protocolKey.DATA]
    for item in data:
      count += 1
      name = list(item.keys()).pop()
      if protocolKey.DATA in item[name]:
        count += count_depth(item[name])

  return count


def count_to_path(root, path):
  if not protocolKey.DATA in root:
    return None
  else:
    data = root[protocolKey.DATA]

  count = 0
  if path == None:
    return count_depth(root)

  search = path[0]

  for item in data:
    # Expect only one key value pair per data item
    key = list(item.keys()).pop()
    count += 1
    if key != search:
      if protocolKey.TYPE in item[key]:
        continue
      else:
        count += count_depth(item[key])
    else:
      if len(path) > 1:
        incr = count_to_path(item[search], path[1:])
        if (incr != None):
          count += incr
        else:
          return None

      break

  else:
    # search item was not found
    return None

  return count


def get_struct(root, path):
  if path == []:
    return root

  if protocolKey.DATA in root:
    data = root[protocolKey.DATA]
  else:
    return None

  for item in data:
    if path[0] in item.keys():
      if len(path) == 1:
        return item[path[0]]
      else:
        return get_struct(item[path[0]], path[1:])
    else:
      continue
  else:
    return None

def extract_types(root, path):
  start = get_struct(root, path)
  types = []
  if start != None:
    if protocolKey.TYPE in start.keys():
      types.append(start[protocolKey.TYPE])
    else:
      if protocolKey.DATA in start.keys():
        for item in start[protocolKey.DATA]:
          name = list(item.keys()).pop()
          types = types + extract_types(item[name], [])

  return types

def extract_decendants(root, path):
  start = get_struct(root, path)
  decendants = []
  if start != None:
    if protocolKey.DATA in start.keys():
      for item in start[protocolKey.DATA]:
        name = list(item.keys()).pop()
        next_decendants = extract_decendants(item[name], [])
        if next_decendants == [""]:
          decendants.append(name)
        else:
          for branch in next_decendants:
            decendants.append("/".join([name, branch]))
    else:
      return [""]

  return decendants

def extract_branches(root, path):
  start = get_struct(root, path)
  decendants = []
  if start != None:
    if protocolKey.DATA in start.keys():
      for item in start[protocolKey.DATA]:
        name = list(item.keys()).pop()
        decendants.append(name)
        next_decendants = extract_branches(item[name], [])
        if next_decendants != [""]:
          for branch in next_decendants:
            decendants.append("/".join([name, branch]))
    else:
      return [""]

  return decendants

def clamp(value, min_value, max_value):
  return max(min_value, min(value, max_value))

def encode_types(item, typeof):
  if typeof == "u8":
    return "{:02x}".format(clamp(item, 0x00, 0xff))
  elif typeof == "u16":
    return "{:04x}".format(clamp(item, 0x0000, 0xffff))
  elif typeof == "u32":
    return "{:08x}".format(clamp(item, 0x00000000, 0xffffffff))
  elif typeof == "u64":
    return "{:016x}".format(clamp(item, 0x0000000000000000, 0xffffffffffffffff))
  if typeof == "i8":
    item = clamp(item, -0x80, 0x7F)
    return "{:02x}".format(item + 0x100 if item < 0 else item)
  elif typeof == "i16":
    item = clamp(item, -0x8000, 0x7FFF)
    return "{:04x}".format(item + 0x10000 if item < 0 else item)
  elif typeof == "i32":
    item = clamp(item, -0x80000000, 0x7FFFFFFF)
    return "{:08x}".format(item + 0x100000000 if item < 0 else item)
  elif typeof == "i64":
    item = clamp(item, -0x8000000000000000, 0x7FFFFFFFFFFFFFFF)
    return "{:016x}".format(item + 0x10000000000000000 if item < 0 else item)
  elif typeof == "string":
    return item
  elif typeof == "bool":
    return "1" if item == True else "0"
  elif typeof == "float":
    return ''.join(format(x, '02x') for x in struct.pack('>f', item))
  elif typeof == "double":
    return ''.join(format(x, '02x') for x in struct.pack('>d', item))
  elif isinstance(typeof, list):
    if item in typeof:
      x = typeof.index(item)
      return "{:02x}".format(clamp(x, 0x00, 0xff))
    else:
      return ""
  else:
    return ""

def decode_unsigned(item, bits):
  try:
    return clamp(int(item, 16), 0, (0x1 << bits) - 1)
  except:
    return 0

def decode_signed(item, bits):
  try:
    value = int(item, 16)
    min_value = 0x1 << (bits - 1)
    if value > min_value:
      value -= 0x1 << (bits)

    return clamp(value, -min_value, min_value -1)
  except:
    return 0

def decode_types(item, typeof):
  if typeof == "u8":
    return decode_unsigned(item, 8)
  elif typeof == "u16":
    return decode_unsigned(item, 16)
  elif typeof == "u32":
    return decode_unsigned(item, 32)
  elif typeof == "u64":
    return decode_unsigned(item, 64)
  if typeof == "i8":
    return decode_signed(item, 8)
  elif typeof == "i16":
    return decode_signed(item, 16)
  elif typeof == "i32":
    return decode_signed(item, 32)
  elif typeof == "i64":
    return decode_signed(item,64)
  elif typeof == "string":
    return item
  elif typeof == "bool":
    return True if item == "1" else False
  elif typeof == "float":
    [x] = struct.unpack('>f', bytearray.fromhex(item))
    return x
  elif typeof == "double":
    [x] = struct.unpack('>d', bytearray.fromhex(item))
    return x
  elif isinstance(typeof, list):
    x = decode_unsigned(item, 8)
    if x < len(typeof):
      return typeof[x]
    else:
      return None
  else:
    return None

class Helpers():
  def generate_maps(protocol):
    encode_map = {}
    decode_map = {}
    count = count_to_path(protocol, None)
    # TODO Track address depth and addr
    addr_path = []
    addr = 0
    prev_depth = 0
    max_depth = -1
    branches = extract_branches(protocol, [])
    roots = []
    for branch in branches:
      roots.append(get_struct(protocol, branch.split('/')))

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
      ends = extract_decendants(root, [])
      types = extract_types(root, [])
      for end in ends:
        if end != "":
          data_branch = '/'.join([branch, end])
        else:
          data_branch = branch
        data_branches.append(data_branch)


      encode_map[branch] = ItemData(addr=addr, path=branch, data_branches=data_branches, types=types)
      decode_map[addr] = encode_map[branch]
    return (encode_map, decode_map)



class Codec():
  def __init__(self, protocol_file_path):
    with open(protocol_file_path, "r") as protocol_file:
      self.protocol = json.load(protocol_file)
    (self.encode_map, self.decode_map) = Helpers.generate_maps(self.protocol)
    self.address_map = {}

    self._generate_category_map()


  def encode(self, packets):
    if isinstance(packets, packet.Packet):
      packets = [packets]
    elif not isinstance(packets, list):
      return ""

    encoded = ""
    for _packet in packets:
      if encoded != "":
        encoded += self.protocol["end"]

      encoded += self.protocol["category"][_packet.category]

      internal = ""

      paths_and_payloads = tuple(zip(_packet.paths, _packet.payloads))
      for (ppath, ppayload) in paths_and_payloads:
        if ppath != None:
          if internal != "":
            internal += self.protocol["compound"]

          path = ppath.split("/")
          root = get_struct(self.protocol, [path[0]])

          if ppath in self.encode_map:
            encode_data = self.encode_map[ppath]
          else:
            print("invalid address: {}".format(ppath))
            return "".encode("utf-8")

          internal += encode_data.addr

          if ppayload != None:

            count = min(len(encode_data.types), len(ppayload))
            for i in range(count):
              internal += self.protocol["separator"]
              internal += encode_types(ppayload[i], encode_data.types[i])

      encoded += internal

    encoded += self.protocol["end"]
    return encoded.encode('utf-8')


  ## Decodes an incoming packet stream
  # Inputs: <byte-string> encoded
  # Returns: Tuple(<byte-string> remainder, Array[<packet>] Packets)
  #
  def decode(self, encoded):
    strings = encoded.split(self.protocol["end"].encode('utf-8'))
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
      category = self.category_from_start(start)
      _packet = packet.Packet(category)
      subpackets = string[1:].split(self.protocol["compound"])
      for subpacket in subpackets:
        parts = subpacket.split(self.protocol["separator"])
        if parts != ['']:
          payload = []
          addr = parts[0]
          decode_data = self.decode_map[addr]

          for (item, typeof) in tuple(zip(parts[1:], decode_data.types)):
            payload.append(decode_types(item, typeof))

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

  def category_from_start(self, start):
    if start in self.category_map.keys():
      return self.category_map[start]
    else:
      return None

  def _generate_category_map(self):
    self.category_map = {}
    for key in self.protocol["category"].keys():
      self.category_map[self.protocol["category"][key]] = key


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




