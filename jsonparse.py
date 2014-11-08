#!/usr/bin/python3.4
import json
from pprint import pprint
with open("data.txt","r") as file:
  a=json.load(file)

print(json.dumps(a, sort_keys=True, indent=4))
