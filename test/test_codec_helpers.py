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

class TestPathFromCount():
  def setup_method(self):
    self.root = countries_root

  def test_zero_counts(self):
    expected = []
    expected_count = 0
    (result, result_count) = codec.path_from_count(self.root, 0)
    assert(result == expected)
    assert(result_count == expected_count)

  def test_simple_counts(self):
    expected = ["NZ", "Auckland", "Avondale"]
    expected_count = 0
    (result, result_count) = codec.path_from_count(self.root, 4)
    assert(result == expected)
    assert(result_count == expected_count)

  def test_complex_counts(self):
    expected = ["NZ", "Napier"]
    expected_count = 0
    (result, result_count) = codec.path_from_count(self.root, 6)
    assert(result == expected)
    assert(result_count == expected_count)

  def test_no_result(self):
    expected = []
    expected_count = 3
    (result, result_count) = codec.path_from_count(self.root, 10)
    assert(result == expected)
    assert(result_count == expected_count)



class TestFromAddress():
  def setup_method(self):
    protocol_file_path = CONFIG_PATH
    self.codec = codec.Codec(protocol_file_path)

  def test_address_map(self):
    assert("0000" in self.codec.address_map.keys())
    assert("1000" in self.codec.address_map.keys())
    assert("1100" in self.codec.address_map.keys())
    assert("2000" in self.codec.address_map.keys())
    assert("8000" in self.codec.address_map.keys())
    assert("1200" in self.codec.address_map.keys())
    assert(self.codec.address_map["0000"] == "protocol")
    assert(self.codec.address_map["1000"] == "ping")
    assert(self.codec.address_map["1100"] == "health")
    assert(self.codec.address_map["2000"] == "typecheck")
    assert(self.codec.address_map["8000"] == "control")
    assert(self.codec.address_map["1200"] == "imu")

  def test_mapped_root_path_from_address(self):
    expected = "protocol"
    result = self.codec.path_from_address("0000")
    assert(expected == result)

  def test_mapped_root_struct_from_address(self):
    expected = self.codec.protocol["_data"][0]["protocol"]
    result = self.codec.struct_from_address("0000")
    assert(expected == result)

  def test_mapped_path_from_address(self):
    expected = "protocol/version"
    result = self.codec.path_from_address("0001")
    assert(expected == result)

  def test_mapped_complex_path_from_address(self):
    expected = "control/manual/speed"
    result = self.codec.path_from_address("8004")
    assert(expected == result)

  def test_mapped_control(self):
    expected = "control"
    result = self.codec.path_from_address("8000")
    assert(expected == result)

  def test_no_path(self):
    expected = ""
    result = self.codec.path_from_address("9000")
    assert(expected == result)

  def test_invalid_path(self):
    expected = ""
    result = self.codec.path_from_address("invalid")
    assert(expected == result)



