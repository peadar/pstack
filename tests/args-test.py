#!/usr/bin/python3
# This tests argument printing works to some extent

import pstack
import re
import os

print("test dir: %s" % os.getcwd())

text, stderr = pstack.TEXT(["./args"])
assert re.search('aFunctionWithArgs.*msg=0x[0-9a-f]+ "tweet", value=42', text), \
      f"expected to see frame for 'aFunctionWithArgs' in {text}, error {stderr}"
