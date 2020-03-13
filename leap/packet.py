# Copyright © 2020 Hoani Bryson
# License: MIT (https://mit-license.org/)
#
# Packet
#
# L3aP packet for describing data fields
#

class Packet():
  def __init__(self, category, path=None, payload=None):
    self.category = category
    self.paths = []
    self.payloads = []
    if path != None:
      self.add(path, payload)

  def add(self, path, payload=None):
    self.paths.append(path)
    if isinstance(payload, tuple) == False and payload != None:
      self.payloads.append(tuple([payload]))
    else:
      self.payloads.append(payload)

  def unpack(self, codec):
    return codec.unpack(self)


