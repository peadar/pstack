#!/usr/bin/python
# This tests argument printing works to some extent

import subprocess,json
import coremonitor
import os.path
import re

cm = coremonitor.CoreMonitor(["tests/asserttext"])

text = subprocess.check_output(["./pstack", "-a", cm.core()])

assertfailframe = re.compile(r'__assert_fail[^_].*assertion="(?P<assertion>[^"]*)"' +
                        r'.*file="(?P<filename>[^"]*)".*line=(?P<line>[0-9a-fx]*)')
res = assertfailframe.search(text)

print("search result: filename (%s)" % res.group("filename"))
print("search result: assertion (%s)" % res.group("filename"))
print("search result: line (%s)" % res.group("line"))
print("pstack output: %s" % text)

assert res.group("assertion") == "1 + 1 == 3"
assert os.path.basename(res.group("filename")) == "asserttext.cc"
assert int(res.group("line"), 0) == 7
