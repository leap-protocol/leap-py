# Copyright © 2020 Hoani Bryson
# License: MIT (https://mit-license.org/)
#
# Explore
#
# Exploration functions for breaking protocol data into indexable data
#


from . import protocolKey

def count_depth(root):
  count = 0

  if protocolKey.DATA in root:
    data = root[protocolKey.DATA]
    for item in data:
      count += 1
      name = list(item.keys()).pop()
      if protocolKey.DATA in item[name]:
        count += count_depth(item[name])

  return count


def count_to_path(root, path):
  if not protocolKey.DATA in root:
    return None
  else:
    data = root[protocolKey.DATA]

  count = 0
  if path == None:
    return count_depth(root)

  search = path[0]

  for item in data:
    # Expect only one key value pair per data item
    key = list(item.keys()).pop()
    count += 1
    if key != search:
      if protocolKey.TYPE in item[key]:
        continue
      else:
        count += count_depth(item[key])
    else:
      if len(path) > 1:
        incr = count_to_path(item[search], path[1:])
        if (incr != None):
          count += incr
        else:
          return None

      break

  else:
    # search item was not found
    return None

  return count


def get_struct(root, path):
  if path == []:
    return root

  if protocolKey.DATA in root:
    data = root[protocolKey.DATA]
  else:
    return None

  for item in data:
    if path[0] in item.keys():
      if len(path) == 1:
        return item[path[0]]
      else:
        return get_struct(item[path[0]], path[1:])
    else:
      continue
  else:
    return None

def extract_types(root, path):
  start = get_struct(root, path)
  types = []
  if start != None:
    if protocolKey.TYPE in start.keys():
      types.append(start[protocolKey.TYPE])
    else:
      if protocolKey.DATA in start.keys():
        for item in start[protocolKey.DATA]:
          name = list(item.keys()).pop()
          types = types + extract_types(item[name], [])

  return types

def extract_decendants(root, path):
  start = get_struct(root, path)
  decendants = []
  if start != None:
    if protocolKey.DATA in start.keys():
      for item in start[protocolKey.DATA]:
        name = list(item.keys()).pop()
        next_decendants = extract_decendants(item[name], [])
        if next_decendants == [""]:
          decendants.append(name)
        else:
          for branch in next_decendants:
            decendants.append("/".join([name, branch]))
    else:
      return [""]

  return decendants

def extract_branches(root, path):
  start = get_struct(root, path)
  branches = []
  if start != None:
    if protocolKey.DATA in start.keys():
      for item in start[protocolKey.DATA]:
        name = list(item.keys()).pop()
        branches.append(name)
        next_branches = extract_branches(item[name], [])
        if next_branches != [""]:
          for branch in next_branches:
            branches.append("/".join([name, branch]))
    else:
      return [""]

  return branches