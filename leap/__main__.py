
if __name__ == "__main__":
  import argparse

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
        { "grand-child-2": { "type": "float"  } },
      ] } },
      { "child-2": { "type": "none" } },
    ] } },
    { "item-2": { "addr": "2000", "type":  "none" } }
  ]
}
"""

  parser = argparse.ArgumentParser(description='Generate an empty leap protocol config file')
  parser.add_argument(
    'filename',
    help="Protocol config filename",
    default="protocol",
    type=str
  )
  parser.add_argument(
    '--json',
    help="Generate JSON config",
    action='store_true',
    default=True
  )

  args = parser.parse_args()
  filename = args.filename
  if args.json:
    if filename[-5:] != ".json":
      filename = filename + ".json"

    with open(filename, 'w') as f:
      f.write(json_default)
