from leap.helpers import verify
import json, toml, os


def open_json(filepath):
  with open(filepath, "r") as protocol_file:
    config = json.load(protocol_file)
  return config

def open_toml(filepath):
  with open(filepath, "r") as protocol_file:
    config = toml.load(protocol_file)
  return config

class TestVerifyBasic():
  def setup_method(self):
    self.verifier = verify.Verifier()
    self.valid_json = os.path.dirname(__file__) + "/fake/protocol.json"
    self.valid_small_json = os.path.dirname(__file__) + "/fake/protocol-small.json"
    self.valid_toml = os.path.dirname(__file__) + "/fake/protocol.toml"
    self.valid_small_toml = os.path.dirname(__file__) + "/fake/protocol-small.toml"

  def test_valid_json(self):
    config = open_json(self.valid_json)
    assert(self.verifier.verify(config))

  def test_valid_small_json(self):
    config = open_json(self.valid_small_json)
    assert(self.verifier.verify(config))

  def test_valid_toml(self):
    config = open_toml(self.valid_toml)
    assert(self.verifier.verify(config))

  def test_valid_small_toml(self):
    config = open_toml(self.valid_small_toml)
    assert(self.verifier.verify(config))

  def test_valid_empty(self):
    config = {}
    assert(self.verifier.verify(config) == False)


class TestVerifyData():
  def setup_method(self):
    self.verifier = verify.Verifier()
    self.valid = os.path.dirname(__file__) + "/fake/protocol.json"
    self.config = open_json(self.valid)

  def test_no_data(self):
    self.config.pop('data', None)
    assert(self.verifier.verify(self.config) == False)

  def test_incorrect_data_type(self):
    self.config['data'] = {'item': {"type": "string"}}
    assert(self.verifier.verify(self.config) == False)

  def test_data_is_empty(self):
    self.config['data'] = []
    assert(self.verifier.verify(self.config) == False)

  def test_data_contains_the_wrong_items(self):
    self.config['data'] = [1, 2]
    assert(self.verifier.verify(self.config) == False)

  def test_item_has_no_data(self):
    self.config['data'] = [{}]
    assert(self.verifier.verify(self.config) == False)

  def test_item_has_too_many_keys(self):
    self.config['data'] = [{"item1": {"type": "string"}, "item2": {"type": "string"}}]
    assert(self.verifier.verify(self.config) == False)

  def test_item_has_an_empty_key(self):
    self.config['data'] = [{"": {"type": "string"}}]
    assert(self.verifier.verify(self.config) == False)

  def test_item_key_must_be_string(self):
    self.config['data'] = [{2: {"type": "string"}}]
    assert(self.verifier.verify(self.config) == False)

  def test_item_has_whitespace_in_key(self):
    self.config['data'] = [{"an item": {"type": "string"}}]
    assert(self.verifier.verify(self.config) == False)

  def test_item_has_invalid_character_in_key(self):
    self.config['data'] = [{"an/item": {"type": "string"}}]
    assert(self.verifier.verify(self.config) == False)

  def test_item_has_invalid_value_type(self):
    self.config['data'] = [{"item": 1}]
    assert(self.verifier.verify(self.config) == False)

  def test_item_has_empty_map(self):
    self.config['data'] = [{"item": {}}]
    assert(self.verifier.verify(self.config) == False)

  def test_item_does_not_contain_data_or_type(self):
    self.config['data'] = [{"item": {"addr": "0000"}}]
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_address_value_type(self):
    self.config['data'][0]['protocol']['addr'] = 0x1000
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_address_too_big(self):
    self.config['data'][0]['protocol']['addr'] = "10000"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_address_too_small(self):
    self.config['data'][0]['protocol']['addr'] = "100"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_address_not_a_number(self):
    self.config['data'][0]['protocol']['addr'] = "FIVE"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_address_not_hex(self):
    self.config['data'][0]['protocol']['addr'] = "55.5"
    assert(self.verifier.verify(self.config) == False)

  def test_cant_have_type_and_data(self):
    self.config['data'][0]['protocol']['type'] = "bool"
    assert(self.verifier.verify(self.config) == False)

  def test_type_not_string(self):
    self.config['data'][1]['ping']['type'] = 1
    assert(self.verifier.verify(self.config) == False)

  def test_type_not_valid(self):
    self.config['data'][1]['ping']['type'] = 'invalid'
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_enum_types(self):
    self.config['data'][1]['ping']['type'] = [1, 2, 3]
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_enum_strings(self):
    self.config['data'][1]['ping']['type'] = ["test", "test?"]
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_enum_empty_string(self):
    self.config['data'][1]['ping']['type'] = ["test", ""]
    assert(self.verifier.verify(self.config) == False)

  def test_addr_must_increase(self):
    self.config['data'][0]['protocol']['addr'] = "2000"
    assert(self.verifier.verify(self.config) == False)

  def test_addr_exceeds_limit(self):
    self.config['data'].append({ 'new' : { "addr": "FFFF", "type": "u8" }})
    self.config['data'].append({ 'overflow' : { "type": "u8" }})
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_buried_deep(self):
    self.config['data'][3]["imu"]["data"][1]["gyros"]["data"][2]["z"] = { "type": "invalid"}
    assert(self.verifier.verify(self.config) == False)


class TestVerifySymbols():
  def setup_method(self):
    self.verifier = verify.Verifier()
    self.valid = os.path.dirname(__file__) + "/fake/protocol.json"
    self.config = open_json(self.valid)

  def test_no_separator(self):
    self.config.pop('separator', None)
    assert(self.verifier.verify(self.config) == False)

  def test_no_compound(self):
    self.config.pop('compound', None)
    assert(self.verifier.verify(self.config) == False)

  def test_no_end(self):
    self.config.pop('end', None)
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_separator_type(self):
    self.config['separator'] = dict()
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_compound_type(self):
    self.config['compound'] = 1
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_end_type(self):
    self.config['end'] = ["?"]
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_separator_length(self):
    self.config['separator'] = "::"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_compound_length(self):
    self.config['compound'] = ""
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_end_length(self):
    self.config['end'] = "><"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_separator_charater(self):
    self.config['separator'] = "9"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_compound_character(self):
    self.config['compound'] = "b"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_end_character(self):
    self.config['end'] = "A"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_separator_is_compound(self):
    self.config['separator'] = self.config['compound']
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_separator_is_end(self):
    self.config['separator'] = self.config['end']
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_end_is_compound(self):
    self.config['end'] = self.config['compound']
    assert(self.verifier.verify(self.config) == False)

class TestVerifyCategory():
  def setup_method(self):
    self.verifier = verify.Verifier()
    self.valid = os.path.dirname(__file__) + "/fake/protocol.json"
    self.config = open_json(self.valid)

  def test_no_category(self):
    self.config.pop('category', None)
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_length(self):
    self.config['category'] = dict()
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_key(self):
    self.config['category'][1] = "L"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_key_whitespace(self):
    self.config['category']["L O"] = "L"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_key_period(self):
    self.config['category'][".in"] = "L"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_key_empty(self):
    self.config['category'][""] = "L"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_value_type(self):
    self.config['category']["tes"] = True
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_value_length(self):
    self.config['category']["tes"] = "TE"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_value_symbol(self):
    self.config['category']["tes"] = "."
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_value_number(self):
    self.config['category']["tes"] = "0"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_category_value_case(self):
    self.config['category']["tes"] = "l"
    assert(self.verifier.verify(self.config) == False)

class TestVerifyVersion():
  def setup_method(self):
    self.verifier = verify.Verifier()
    self.valid = os.path.dirname(__file__) + "/fake/protocol.json"
    self.config = open_json(self.valid)

  def test_no_version(self):
    self.config.pop('version', None)
    assert(self.verifier.verify(self.config) == False)

  def test_no_major_version(self):
    self.config['version'].pop('major', None)
    assert(self.verifier.verify(self.config) == False)

  def test_no_minor_version(self):
    self.config['version'].pop('minor', None)
    assert(self.verifier.verify(self.config) == False)

  def test_no_patch_version(self):
    self.config['version'].pop('patch', None)
    assert(self.verifier.verify(self.config) == False)

  def test_too_many_version_items(self):
    self.config['version']['fake'] = 2
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_major_version(self):
    self.config['version']['major'] = 1.2
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_minor_version(self):
    self.config['version']['minor'] = "2"
    assert(self.verifier.verify(self.config) == False)

  def test_invalid_patch_version(self):
    self.config['version']['patch'] = None
    assert(self.verifier.verify(self.config) == False)




