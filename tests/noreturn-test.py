#!/usr/bin/python2
# This tests argument printing works to some extent

import pstack

def child():
    import os
    print os.getcwd()
    import ctypes
    dll = ctypes.CDLL("tests/libnoreturn.so")
    dll.thisFunctionWontReturn()

process = pstack.JSON(None, child)
stack = process[0]["ti_stack"]
frames = [ frame for frame in stack if "die" in frame and frame["die"] == "thisFunctionWontReturn" ]
assert len(frames) == 1, "we should see our function on the stack"

frame = frames[0]
symbol = frame["symbol"]

# Make sure we've actually tested the case where the instruction pointer is just
# after the actual function definition
assert symbol["st_value"] + symbol["st_size"] + frame["loadaddr"] == frame["ip"]
