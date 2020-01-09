from leap import codec, packet
import json, os

VALID_JSON_CONFIG_PATH = os.path.dirname(__file__) + "/fake/protocol.json"
INVALID_JSON_CONFIG_PATH = os.path.dirname(__file__) + "/fake/invalid-json.json"
VALID_TOML_CONFIG_PATH = os.path.dirname(__file__) + "/fake/protocol-small.toml"


class TestCodecValid():

  def test_valid_json_file(self):
    protocol_file_path = VALID_JSON_CONFIG_PATH
    self.codec = codec.Codec(protocol_file_path)

    assert(self.codec.valid())

  def test_valid_toml_file(self):
    protocol_file_path = VALID_TOML_CONFIG_PATH
    self.codec = codec.Codec(protocol_file_path)

    assert(self.codec.valid())


  def test_invalid_json_file(self):
    protocol_file_path = INVALID_JSON_CONFIG_PATH
    self.codec = codec.Codec(protocol_file_path)

    assert(self.codec.valid() == False)

