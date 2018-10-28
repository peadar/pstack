#!/usr/bin/python

import subprocess,json
import coremonitor

cm = coremonitor.CoreMonitor( [ "tests/badfp" ] )

threads = json.loads(subprocess.check_output(["./pstack", "-j", cm.core() ]))
assert len(threads) == 1
thread = threads[0]
stack = thread["ti_stack"]

assert stack[0]["ip"] == 0 # instruction pointer 0 at top-of-stack
assert stack[1]["function"] == "main" # called from main
