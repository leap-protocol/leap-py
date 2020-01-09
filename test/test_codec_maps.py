from leap import codec, packet
from leap.helpers import itemData
import json, os

CONFIG_PATH = os.path.dirname(__file__) + "/fake/protocol-small.toml"

class TestEncodeMap():
  def setup_method(self):
    protocol_file_path = CONFIG_PATH
    self.codec = codec.Codec(protocol_file_path)

  def test_map_length(self):
    expected = 8
    result = len(list(self.codec.encode_map.keys()))
    assert( result == expected )

  def test_map_holds_encode_data(self):
    for item in self.codec.encode_map.values():
      assert(isinstance(item, itemData.ItemData))

  def test_correct_keys(self):
    expected_keys = [ "protocol", "protocol/version", "protocol/version/major", "protocol/version/minor", "protocol/version/patch",
      "protocol/name", "protocol/app", "ping" ]
    for expected, result in zip(expected_keys, self.codec.encode_map.keys()):
      assert(expected == result)

  def test_correct_address_data(self):
    expected_addr = [ "1000", "1001", "1002", "1003", "1004", "1005", "1a00", "2000" ]
    for expected, item in zip(expected_addr, self.codec.encode_map.values()):
      assert(expected == item.addr)

  def test_correct_branch_end_data(self):
    expected_branches = [
      [ "protocol/version/major", "protocol/version/minor", "protocol/version/patch", "protocol/name", "protocol/app" ],
      [ "protocol/version/major", "protocol/version/minor", "protocol/version/patch" ],
      [ "protocol/version/major" ],
      [ "protocol/version/minor" ],
      [ "protocol/version/patch" ],
      [ "protocol/name" ],
      [ "protocol/app" ],
      [ "ping" ]
    ]
    for expected, item in zip(expected_branches, self.codec.encode_map.values()):
      assert(expected == item.data_branches)

  def test_correct_types_data(self):
    expected_types = [
      [ "u8", "u8", "u16", "string", "string" ],
      [ "u8", "u8", "u16" ],
      [ "u8" ],
      [ "u8" ],
      [ "u16" ],
      [ "string" ],
      [ "string" ],
      [ "none" ]
    ]
    for expected, item in zip(expected_types, self.codec.encode_map.values()):
      assert(expected == item.types)





class TestDecodeMap():
  def setup_method(self):
    protocol_file_path = CONFIG_PATH
    self.codec = codec.Codec(protocol_file_path)

  def test_map_length(self):
    expected = 8
    result = len(list(self.codec.decode_map.keys()))
    assert( result == expected )

  def test_map_holds_decode_data(self):
    for item in self.codec.decode_map.values():
      assert(isinstance(item, itemData.ItemData))

  def test_correct_keys(self):
    expected_keys = [ "1000", "1001", "1002", "1003", "1004", "1005", "1a00", "2000" ]
    for expected, result in zip(expected_keys, self.codec.decode_map.keys()):
      assert(expected == result)

  def test_correct_path_data(self):
    expected_path = [ "protocol", "protocol/version", "protocol/version/major", "protocol/version/minor", "protocol/version/patch",
      "protocol/name", "protocol/app", "ping" ]
    for expected, item in zip(expected_path, self.codec.decode_map.values()):
      assert(expected == item.path)

  def test_correct_branch_end_data(self):
    expected_branches = [
      [ "protocol/version/major", "protocol/version/minor", "protocol/version/patch", "protocol/name", "protocol/app" ],
      [ "protocol/version/major", "protocol/version/minor", "protocol/version/patch" ],
      [ "protocol/version/major" ],
      [ "protocol/version/minor" ],
      [ "protocol/version/patch" ],
      [ "protocol/name" ],
      [ "protocol/app" ],
      [ "ping" ]
    ]
    for expected, item in zip(expected_branches, self.codec.decode_map.values()):
      assert(expected == item.data_branches)

  def test_correct_types_data(self):
    expected_types = [
      [ "u8", "u8", "u16", "string", "string" ],
      [ "u8", "u8", "u16" ],
      [ "u8" ],
      [ "u8" ],
      [ "u16" ],
      [ "string" ],
      [ "string" ],
      [ "none" ]
    ]
    for expected, item in zip(expected_types, self.codec.decode_map.values()):
      assert(expected == item.types)


