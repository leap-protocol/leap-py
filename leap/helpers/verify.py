# Copyright © 2020 Hoani Bryson
# License: MIT (https://mit-license.org/)
#
# Verify
#
# Verifies correctness of L3ap protocol configuration files
#

import re, json, toml
from . import protocolKey


def verify(config_file_path):
  try:
    config_file = open(config_file_path, "r")
  except:
    print("File {} cannot be opened, maybe it doesn't exist?".format(config_file_path))
    return False
  config_file.close()

  invalid = False

  try:
    with open(config_file_path, "r") as config_file:
      config = json.load(config_file)
  except:
    try:
      with open(config_file_path, "r") as config_file:
        config = toml.load(config_file)
    except:
      invalid = True

  if config == {}:
    invalid = True

  if invalid:
    print("Verification of {} failed".format(config_file_path))
    print("Invalid JSON/TOML")
    config_file.close()
    return False

  config_file.close()

  v = Verifier()

  result = v.verify(config)
  if result is False:
    print("Verification of {} failed".format(config_file_path))
    v.print_failure()
    print(config)
    return False
  else:
    print("Verification of {} passed".format(config_file_path))
    return True


class Verifier:
  def __init__(self):
    self.section = ""
    self.failure = ""
    self.addr = []
    self.current_addr = None
    self.depth = -1

  def verify(self, config):
    self.__init__()

    if len(config) == 0:
      self.section = "Config"
      self.print_failure = "Configuration is empty"
      return False


    if self.verify_category(config) == False:
      self.section = "Category"
      return False

    if self.verify_version(config) == False:
      self.section = "Version"
      return False

    if self.verify_symbols(config) == False:
      self.section = "Symbols"
      return False

    if self.verify_data(config, "root") == False:
      self.section = "Data"
      return False

    return True

  def update_addr(self, addr, depth):
    if addr == None:
      if self.current_addr == None:
        next_addr = 0
      else:
        next_addr = int(self.current_addr, 16)
        next_addr += 1

      if self.depth < depth:
        self.addr.append(0)
    else:
      if self.depth >= depth:
        self.addr[depth] = addr
      else:
        self.addr.append(addr)

      next_addr = 0
      for i in range(depth + 1):
        next_addr += int(self.addr[i], 16)

    self.depth = max(self.depth, depth)

    if self.current_addr == None:
      self.current_addr = "{:04x}".format(next_addr)
      return True
    elif next_addr <= int(self.current_addr, 16):
      self.failure = "Next address {:04x} is lower than previous address {:04x}".format(next_addr, int(self.current_addr, 16))
      return False
    elif next_addr > 0xFFFF:
      self.failure = "Next address 0x{:x} has overrun 0xFFFF".format(next_addr)
      return False
    else:
      self.current_addr = "{:04x}".format(next_addr)
      return True



  def print_failure(self):
    if self.section != "":
      print("---")
      print("Config Verification Failed")
      print("")
      print("Section: {}".format(self.section))
      print("Failure: {}".format(self.failure))
      print("---")

  def verify_data(self, config, branch):
    if not "data" in config:
      self.failure = "Missing data key in {} data structure".format(branch)
      return False

    data = config["data"]
    if not isinstance(data, list):
      self.failure = "data in {} must be an array of items".format(branch)
      return False

    if len(data) == 0:
      self.failure = "data in {} is empty".format(branch)
      return False

    for item in data:
      if self.verify_item(item, branch) == False:
        return False

    return True


  def verify_item(self, item, branch):
    if not isinstance(item, dict):
      self.failure = "data items in {} must be objects".format(branch)
      return False

    if len(item.keys()) != 1:
      self.failure = "data items in {} must have only one key-pair per object".format(branch)
      return False

    for key in item.keys():
      if not isinstance(key, str):
        self.failure = "data item key {} in {} invalid. Keys must be strings containing only alpha numeric, dash(-) and underscore(_) characters ".format(key, branch)
        return False

      if re.match(r"^[A-Za-z0-9\-_]+$", key) is None:
        self.failure = "data item key {} in {} invalid. Keys may only contain alpha numeric, dash(-) and underscore(_) characters ".format(key, branch)
        return False

      if branch == "root":
        branch = key
      else:
        branch = branch + "/" + key

      if self.verify_values(item[key], branch) == False:
        return False

    return True

  def verify_values(self, values, branch):
    if not isinstance(values, dict):
      self.failure = "value of {} must be an object".format(branch)
      return False

    if not (protocolKey.DATA in values.keys()) != (protocolKey.TYPE in values.keys()):
      self.failure = 'object in {} must have either a "{}" or "{}" key, but not both'.format(branch, protocolKey.DATA, protocolKey.TYPE)
      return False

    if protocolKey.ADDR in values.keys():
      if self.verify_address(values[protocolKey.ADDR], branch) == False:
        return False

      if self.update_addr(values[protocolKey.ADDR], branch.count('/')) == False:
        self.failure += " at {}".format(branch)
        return False
    else:
      if self.update_addr(None, branch.count('/')) == False:
        self.failure += " at {}".format(branch)
        return False

    if protocolKey.TYPE in values.keys():
      if self.verify_type(values[protocolKey.TYPE], branch) == False:
        return False

    if protocolKey.DATA in values.keys():
      if self.verify_data(values, branch) == False:
        return False

    return True


  def verify_address(self, addr, branch):
    if not isinstance(addr, str):
      self.failure = '"{}" of {} must be a string'.format(protocolKey.ADDR, branch)
      return False

    if re.match(r"^[A-Fa-f0-9\-_]{4}$", addr) is None:
      self.failure = '"{}" of "{}" in {} invalid. Addresses are four character hexidecimal strings'.format(protocolKey.ADDR, addr, branch)
      return False

    return True


  def verify_type(self, type_, branch):
    valid_types = ['u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64', 'bool', 'float', 'double', 'string', 'none']

    if not (isinstance(type_, str) or isinstance(type_, list)):
      self.failure = '"{}" of {} must be a string (or an array if enum)'.format(protocolKey.TYPE, branch)
      return False

    if isinstance(type_, str):
      if type_ not in valid_types:
        self.failure = 'type "{}" of {} is not a valid type, see docs for more valid types'.format(protocolKey.TYPE, branch)
        return False

    if isinstance(type_, list):
      for item in type_:
        if not isinstance(item, str) or re.match(r"^[A-Za-z0-9\-_]+$", item) is None:
          self.failure = 'items {} in {} array of {} may only be strings using alpha-numeric characters, dashes (-) and underscores (_)'.format(item, protocolKey.TYPE, branch)
          return False


    return True

  def verify_symbols(self, config):
    symbols = ["separator", "compound", "end"]

    for symbol in symbols:
      if symbol not in config:
        self.failure = "Missing {} key in root data structure".format(symbol)
        return False

      if not isinstance(config[symbol], str):
        self.failure = '{} must be assigned to a single character e.g. ">"'
        return False

      if re.match(r'^[\W]{1}$', config[symbol]) == None:
        self.failure = '{} must be a single character and non-alphanumeric e.g. ">"'
        return False

    if (config['separator'] == config['compound'] or
      config['separator'] == config['end'] or
      config['compound'] == config['end']
    ):
      self.failure = '"separator", "compound" and "end" characters must all be different from eachother'
      return False

    return True


  def verify_category(self, config):

    if "category" not in config.keys():
      self.failure = "Missing category key in root data structure"
      return False

    category = config['category']

    if len(category.keys()) == 0:
      self.failure = 'There must be at least one category item'
      return False

    for key in category.keys():
      if not isinstance(key, str):
        self.failure = "Category keys must be strings"
        return False

      if re.match(r"^[A-Za-z0-9\-_]+$", key) is None:
        self.failure = "Category keys may only contain alphanumeric symbols, underscores(_) and dashes (-)"
        return False

    for value in category.values():
      if not isinstance(value, str):
        self.failure = 'A category must be assigned to a single capital letter e.g. "C"'
        return False

      if re.match(r"^[A-Z]{1}$", value) is None:
        self.failure = 'A category must be assigned to a single capital letter e.g. "C"'
        return False

    return True


  def verify_version(self, config):
    if "version" not in config.keys():
      self.failure = "Missing version key in root data structure"
      return False

    version = config["version"]

    segments = ["major", "minor", "patch"]

    for segment in segments:
      if segment not in version.keys():
        self.failure = 'Missing "{}" in "version" data structure'
        return False

      if not isinstance(version[segment], int):
        self.failure = '"version" "{}" must be an integer'
        return False

    if len(version.keys()) != 3:
      self.failure = '"version" must only contain items "major", "minor" and "patch"'
      return False

    return True

