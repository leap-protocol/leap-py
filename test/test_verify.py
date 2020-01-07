from leap.helpers import verify
import json, os


def open_config(filepath):
  with open(filepath, "r") as protocol_file:
    config = json.load(protocol_file)
  return config

class TestVerifyValid():
  def setup_method(self):
    self.verifier = verify.Verifier()
    self.valid = os.path.dirname(__file__) + "/fake/protocol.json"
    self.config = open_config(self.valid)

  def test_is_valid(self):
    assert(self.verifier.verify(self.config))

class TestVerifySymbols():
  def setup_method(self):
    self.verifier = verify.Verifier()
    self.valid = os.path.dirname(__file__) + "/fake/protocol.json"
    self.config = open_config(self.valid)

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
    self.config = open_config(self.valid)

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
    self.config = open_config(self.valid)

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




