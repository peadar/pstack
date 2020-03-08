#!/usr/bin/python

import subprocess,json
import coremonitor

cm = coremonitor.CoreMonitor( [ "tests/badfp" ] )

threads = json.loads(subprocess.check_output(["./pstack", "-j", cm.core() ]))
assert len(threads) == 1
thread = threads[0]
stack = thread["ti_stack"]

assert stack[0]["ip"] == 0 # instruction pointer 0 at top-of-stack
assert stack[1]["die"] == "main" # called from main

# run the test again, with the signal trapped. Ensure that we can see
# the trampoline from the signal handler

cm = coremonitor.CoreMonitor( [ "tests/badfp", "-h" ] )
thread = json.loads(subprocess.check_output(["./pstack", "-j", cm.core()]))[0]["ti_stack"]

# find the frame with the zero instruction pointer
zeroframe = [ idx for (idx, frame) in enumerate(thread) if frame["ip"] == 0 ]
assert(len(zeroframe) == 1)
assert thread[zeroframe[0] - 1]["trampoline"]
