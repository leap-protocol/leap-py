class ItemData:
  def __init__(self, path = "", addr = "0000", data_branches=[], types=[]):
    self.addr = addr
    self.path = path
    self.data_branches = data_branches
    self.types = types