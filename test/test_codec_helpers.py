from leap import codec, packet
from leap.helpers import explore
import json, os

CONFIG_PATH = os.path.dirname(__file__) + "/fake/protocol.json"

countries_root = { "data": [
  { "NZ": { "data": [
    { "Auckland": { "data": [
      { "GlenInnes": { "type": "u16"  } },
      { "Avondale": { "type": "float" } }
    ] } },
    { "Hamilton": {"type": "u8"  } },
    { "Napier": { "type": "bool" } }
  ] } },
  { "Rarotonga": { "type": "i32" } }
] }

class TestGetStruct():
  def setup_method(self):
    self.root = countries_root

  def test_get_none(self):
    expected = None
    result = explore.get_struct(self.root, ["Florida"])
    assert(result == expected)

  def test_get_last(self):
    expected = { "type": "i32" }
    result = explore.get_struct(self.root, ["Rarotonga"])
    assert(result == expected)

  def test_get_none(self):
    expected = None
    result = explore.get_struct(self.root, ["Florida"])
    assert(result == expected)

  def test_get_deep(self):
    expected = { "type": "float" }
    result = explore.get_struct(self.root, ["NZ", "Auckland", "Avondale"])
    assert(result == expected)

  def test_get_another(self):
    expected = { "type": "bool" }
    result = explore.get_struct(self.root, ["NZ", "Napier"])
    assert(result == expected)

  def test_no_path(self):
    expected = self.root
    result = explore.get_struct(self.root, [])
    assert(result == expected)

class TestExtractTypes():
  def setup_method(self):
    protocol_file_path = CONFIG_PATH
    _codec = codec.Codec(protocol_file_path)
    self.data = _codec._config

  def test_simple_type(self):
    expected = ["bool"]
    result = explore.extract_types(self.data, ["ping"])
    assert(result == expected)

  def test_nested_type(self):
    expected = ["u16"]
    result = explore.extract_types(self.data, ["protocol", "version", "patch"])
    assert(result == expected)

  def test_multiple_types(self):
    expected = ["u8", "u8", "u16"]
    result = explore.extract_types(self.data, ["protocol", "version"])
    assert(result == expected)

  def test_multiple_types_nesting(self):
    expected = ["u8", "u8", "u16", "string"]
    result = explore.extract_types(self.data, ["protocol"])
    assert(result == expected)



class TestCountToPath():
  def setup_method(self):
    self.root = countries_root

  def test_none_counts_depth(self):
    expected = 7
    result = explore.count_to_path(self.root, None)
    assert(result == expected)

  def test_basic_one_deep(self):
    expected = 1
    result = explore.count_to_path(self.root, ["NZ"])
    assert(result == expected)

  def test_basic_two_deep(self):
    expected = 2
    result = explore.count_to_path(self.root, ["NZ", "Auckland"])
    assert(result == expected)

  def test_basic_three_deep(self):
    expected = 3
    result = explore.count_to_path(self.root, ["NZ", "Auckland", "GlenInnes"])
    assert(result == expected)

  def test_three_deep(self):
    expected = 4
    result = explore.count_to_path(self.root, ["NZ", "Auckland", "Avondale"])
    assert(result == expected)

  def test_two_deep(self):
    expected = 6
    result = explore.count_to_path(self.root, ["NZ", "Napier"])
    assert(result == expected)

  def test_incorrect_path(self):
    expected = None
    result = explore.count_to_path(self.root, ["NZ", "Christchurch"])
    assert(result == expected)


class TestExtractDecendants():
  def setup_method(self):
    protocol_file_path = CONFIG_PATH
    _codec = codec.Codec(protocol_file_path)
    self.data = _codec._config

  def test_no_decendant(self):
    expected = [""]
    result = explore.extract_decendants(self.data, ["ping"])
    assert(result == expected)

  def test_multiple_decendants(self):
    expected = ["major", "minor", "patch"]
    result = explore.extract_decendants(self.data, ["protocol", "version"])
    assert(result == expected)

  def test_multilevel(self):
    expected = ["version/major", "version/minor", "version/patch", "name"]
    result = explore.extract_decendants(self.data, ["protocol"])
    assert(result == expected)


class TestExtractBranches():
  def setup_method(self):
    protocol_file_path = CONFIG_PATH
    _codec = codec.Codec(protocol_file_path)
    self.data = _codec._config

  def test_none(self):
    expected = [""]
    result = explore.extract_branches(self.data, ["health", "batt", "v"])
    assert(result == expected)

  def test_single(self):
    expected = ["v"]
    result = explore.extract_branches(self.data, ["health", "batt"])
    assert(result == expected)

  def test_multiple(self):
    expected = ["major", "minor", "patch"]
    result = explore.extract_branches(self.data, ["protocol", "version"])
    assert(result == expected)

  def test_multilevel(self):
    expected = ["version", "version/major", "version/minor", "version/patch", "name"]
    result = explore.extract_branches(self.data, ["protocol"])
    assert(result == expected)


