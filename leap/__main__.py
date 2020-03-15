# Copyright © 2020 Hoani Bryson
# License: MIT (https://mit-license.org/)
#
# Main
#
# L3aP Command Line Interface
#


if __name__ == "__main__":
  import argparse, sys

  toml_default = """
separator = ":"
compound = "|"
end = "\\n"

[version]
  major = 1
  minor = 0
  patch = 0

[category]
  get = "G"
  set = "S"
  ack = "A"
  nak = "N"
  sub = "B"
  pub = "P"

[[data]]
  [data.item-1]
    addr = "0000"
    [[data.item-1.data]]
      [data.item-1.data.child-1]
        [[data.item-1.data.child-1.data]]
          grand-child-1 = { type = "u8" }
        [[data.item-1.data.child-1.data]]
          grand-child-2 = { type = "float" }
    [[data.item-1.data]]
      child-2 = { type = "none" }
[[data]]
  item-2 = { addr = "2000", type = "none" }
"""

  json_default = """
{
  "version": {
    "major": 1,
    "minor": 0,
    "patch": 0
  },
  "category": {
    "get": "G",
    "set": "S",
    "ack": "A",
    "nak": "N",
    "sub": "B",
    "pub": "P"
  },
  "separator": ":",
  "compound": "|",
  "end": "\\n",
  "data": [
    { "item-1": { "addr": "0000", "data": [
      { "child-1": { "data": [
        { "grand-child-1": { "type": "u8"  } },
        { "grand-child-2": { "type": "float"  } }
      ] } },
      { "child-2": { "type": "none" } }
    ] } },
    { "item-2": { "addr": "2000", "type":  "none" } }
  ]
}
"""

  parser = argparse.ArgumentParser(description='Leap config file utility')
  parser.add_argument(
    'filename',
    help="config filename",
    default="leap-config",
    type=str
  )
  parser.add_argument(
    '--json',
    help="Generate an empty(ish) JSON leap configuration file",
    action='store_true',
    default=False
  )
  parser.add_argument(
    '--toml',
    help="Generate an empty(ish) TOML leap configuration file",
    action='store_true',
    default=False
  )
  parser.add_argument(
    '--verify',
    help="Verify the contents of a TOML or JSON config file are valid",
    action='store_true',
    default=False
  )

  args = parser.parse_args()
  filename = args.filename
  if args.toml and args.json == False:
    if filename[-5:] != ".toml":
      filename = filename + ".toml"

    with open(filename, 'w') as f:
      f.write(toml_default)
  elif args.json:
    if filename[-5:] != ".json":
      filename = filename + ".json"

    with open(filename, 'w') as f:
      f.write(json_default)
  elif args.verify:
    from .helpers import verify
    if not verify.verify(filename):
      sys.exit(1); # Failed, sorry!

  sys.exit(0)
