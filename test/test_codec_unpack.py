from leap import codec, packet
import json, os

CONFIG_PATH = os.path.dirname(__file__) + "/fake/protocol.json"

class TestPacketPayloadUnpack():
  def setup_method(self):
    protocol_file_path = CONFIG_PATH
    self.codec = codec.Codec(protocol_file_path)

  def test_unpack_simple(self):
    expected = {"protocol/version/major": 5}
    _packet = packet.Packet("pub", "protocol/version/major", 5)
    result = self.codec.unpack(_packet)
    assert(result == expected)

  def test_unpack_multiple(self):
    expected = {
      "protocol/version/major": 5,
      "protocol/version/minor": 4,
      "protocol/version/patch": 3,
    }
    _packet = packet.Packet("pub", "protocol/version", (5, 4, 3))
    result = self.codec.unpack(_packet)
    assert(result == expected)

  def test_unpack_partial(self):
    expected = {
      "protocol/version/major": 5,
      "protocol/version/minor": 4
    }
    _packet = packet.Packet("pub", "protocol/version", (5, 4))
    result = self.codec.unpack(_packet)
    assert(result == expected)

  def test_unpack_overflow(self):
    expected = {
      "protocol/version/major": 5,
      "protocol/version/minor": 4,
      "protocol/version/patch": 3
    }
    _packet = packet.Packet("pub", "protocol/version", (5, 4, 3, 2))
    result = self.codec.unpack(_packet)
    assert(result == expected)

  def test_unpack_settable(self):
    expected = {"typecheck/uint32": 0x12345}
    _packet = packet.Packet("pub", "typecheck/uint32", 0x12345)
    result = self.codec.unpack(_packet)
    assert(result == expected)

  def test_unpack_explore(self):
    expected = {
      "imu/accel/x": 12.0,
      "imu/accel/y": 23.0,
      "imu/accel/z": 45.0,
      "imu/gyros/x": 67.0,
      "imu/gyros/y": 89.0,
      "imu/gyros/z": 12.0,
      "imu/magne/x": 34.0,
      "imu/magne/y": 56.0,
      "imu/magne/z": 78.0
    }
    _packet = packet.Packet("pub", "imu", tuple([12.0, 23.0, 45.0, 67.0, 89.0, 12.0, 34.0, 56.0, 78.0]))
    result = self.codec.unpack(_packet)
    assert(result == expected)

