from leap import codec, packet
import json, os

CONFIG_PATH = os.path.dirname(__file__) + "/fake/protocol-small.json"

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
      assert(isinstance(item, codec.ItemData))

  def test_correct_keys(self):
    expected_keys = [ "protocol", "protocol/version", "protocol/version/major", "protocol/version/minor", "protocol/version/patch",
      "protocol/name", "protocol/app", "ping" ]
    for expected, result in zip(expected_keys, self.codec.encode_map.keys()):
      assert(expected == result)

  def test_correct_address_data(self):
    expected_addr = [ "0000", "0001", "0002", "0003", "0004", "0005", "0100", "1000" ]
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


