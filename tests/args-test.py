#!/usr/bin/python2
# This tests argument printing works to some extent

import pstack
import re

text, _ = pstack.TEXT(["tests/args"])
assert re.search('aFunctionWithArgs.*msg="tweet", value=42', text)
