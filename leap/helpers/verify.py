import re
from . import protocolKey


def verify(config):

  v = Verifier()

  return v.verify(config)

class Verifier:
  def __init__(self):
    self.section = ""
    self.failure = ""

  def verify(self, config):
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

      if re.match(r"^[A-Za-z0-9\-_]+$", key) == None:
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

    if not (protocolKey.DATA in values.keys() or protocolKey.TYPE in values.keys()):
      self.failure = 'object in {} must have either a "{}" or "{}" key'.format(branch, protocolKey.DATA, protocolKey.TYPE)
      return False

    if protocolKey.ADDR in values.keys():
      if self.verify_address(values[protocolKey.ADDR], branch) == False:
        return False

    return True

  def verify_address(self, addr, branch):
    if not isinstance(addr, str):
      self.failure = '"{}" of {} must be a string'.format(protocolKey.ADDR, branch)
      return False
    return True

  def verify_symbols(self, config):
    symbols = ["separator", "compound", "end"]

    for symbol in symbols:
      if not symbol in config:
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

    if not "category" in config.keys():
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

      if re.match(r"^[A-Za-z0-9\-_]+$", key) == None:
        self.failure = "Category keys may only contain alphanumeric symbols, underscores(_) and dashes (-)"
        return False

    for value in category.values():
      if not isinstance(value, str):
        self.failure = 'A category must be assigned to a single capital letter e.g. "C"'
        return False

      if re.match(r"^[A-Z]{1}$", value) == None:
        self.failure = 'A category must be assigned to a single capital letter e.g. "C"'
        return False

    return True


  def verify_version(self, config):
    if not "version" in config.keys():
      self.failure = "Missing version key in root data structure"
      return False

    version = config["version"]

    segments = ["major", "minor", "patch"]

    for segment in segments:
      if not segment in version.keys():
        self.failure = 'Missing "{}" in "version" data structure'
        return False

      if not isinstance(version[segment], int):
        self.failure = '"version" "{}" must be an integer'
        return False

    if len(version.keys()) != 3:
      self.failure = '"version" must only contain items "major", "minor" and "patch"'
      return False


    return True