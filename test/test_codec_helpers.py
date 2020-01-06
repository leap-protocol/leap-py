from leap import codec, packet
import json, os

CONFIG_PATH = os.path.dirname(__file__) + "/fake/protocol.json"

countries_root = { "_data": [
  { "NZ": { "_data": [
    { "Auckland": { "_data": [
      { "GlenInnes": { "_type": "u16"  } },
      { "Avondale": { "_type": "float" } }
    ] } },
    { "Hamilton": {"_type": "u8"  } },
    { "Napier": { "_type": "bool" } }
  ] } },
  { "Rarotonga": { "_type": "i32" } }
] }

class TestGetStruct():
  def setup_method(self):
    self.root = countries_root

  def test_get_none(self):
    expected = None
    result = codec.get_struct(self.root, ["Florida"])
    assert(result == expected)

  def test_get_last(self):
    expected = { "_type": "i32" }
    result = codec.get_struct(self.root, ["Rarotonga"])
    assert(result == expected)

  def test_get_none(self):
    expected = None
    result = codec.get_struct(self.root, ["Florida"])
    assert(result == expected)

  def test_get_deep(self):
    expected = { "_type": "float" }
    result = codec.get_struct(self.root, ["NZ", "Auckland", "Avondale"])
    assert(result == expected)

  def test_get_another(self):
    expected = { "_type": "bool" }
    result = codec.get_struct(self.root, ["NZ", "Napier"])
    assert(result == expected)

  def test_no_path(self):
    expected = self.root
    result = codec.get_struct(self.root, [])
    assert(result == expected)

class TestExtractTypes():
  def setup_method(self):
    protocol_file_path = CONFIG_PATH
    _codec = codec.Codec(protocol_file_path)
    self.data = _codec.protocol

  def test_simple_type(self):
    expected = ["bool"]
    result = codec.extract_types(self.data, ["ping"])
    assert(result == expected)

  def test_nested_type(self):
    expected = ["u16"]
    result = codec.extract_types(self.data, ["protocol", "version", "patch"])
    assert(result == expected)

  def test_multiple_types(self):
    expected = ["u8", "u8", "u16"]
    result = codec.extract_types(self.data, ["protocol", "version"])
    assert(result == expected)

  def test_multiple_types_nesting(self):
    expected = ["u8", "u8", "u16", "string"]
    result = codec.extract_types(self.data, ["protocol"])
    assert(result == expected)



class TestCountToPath():
  def setup_method(self):
    self.root = countries_root

  def test_none_counts_depth(self):
    expected = 7
    result = codec.count_to_path(self.root, None)
    assert(result == expected)

  def test_basic_one_deep(self):
    expected = 1
    result = codec.count_to_path(self.root, ["NZ"])
    assert(result == expected)

  def test_basic_two_deep(self):
    expected = 2
    result = codec.count_to_path(self.root, ["NZ", "Auckland"])
    assert(result == expected)

  def test_basic_three_deep(self):
    expected = 3
    result = codec.count_to_path(self.root, ["NZ", "Auckland", "GlenInnes"])
    assert(result == expected)

  def test_three_deep(self):
    expected = 4
    result = codec.count_to_path(self.root, ["NZ", "Auckland", "Avondale"])
    assert(result == expected)

  def test_two_deep(self):
    expected = 6
    result = codec.count_to_path(self.root, ["NZ", "Napier"])
    assert(result == expected)

  def test_incorrect_path(self):
    expected = None
    result = codec.count_to_path(self.root, ["NZ", "Christchurch"])
    assert(result == expected)





