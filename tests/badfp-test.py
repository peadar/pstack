#!/usr/bin/python2
import pstack

threads, _ = pstack.JSON(["tests/badfp"])
assert len(threads) == 1
thread = threads[0]
stack = thread["ti_stack"]

assert stack[0]["ip"] == 0 # instruction pointer 0 at top-of-stack
assert stack[1]["die"] == "main" # called from main

# run the test again, with the signal trapped. Ensure that we can see
# the trampoline from the signal handler

dump,_ = pstack.JSON( [ "tests/badfp", "-h" ] )
thread = dump[0]["ti_stack"]

# find the frame with the zero instruction pointer
zeroframe = [ idx for (idx, frame) in enumerate(thread) if frame["ip"] == 0 ]
assert(len(zeroframe) == 1)
assert thread[zeroframe[0] - 1]["trampoline"]
