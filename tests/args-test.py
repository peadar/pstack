#!/usr/bin/python3
# This tests argument printing works to some extent

import pstack
import re

text, _ = pstack.TEXT(["tests/args"])
assert re.search('aFunctionWithArgs.*msg=0x[0-9a-f]+ "tweet", value=42', text)
