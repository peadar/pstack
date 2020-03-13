#!/usr/bin/python
# This tests argument printing works to some extent

import subprocess,json
import coremonitor
import os.path
import re

cm = coremonitor.CoreMonitor(["tests/args"])

text = subprocess.check_output(["./pstack", "-a", cm.core()])
assert re.search('aFunctionWithArgs.*msg="tweet", value=42', text)
