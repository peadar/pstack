#!/usr/bin/python3

import pstack
import platform

basicBinaries = [ "basic", "basic-zlib", "basic-zlib-gnu" ]
if platform.machine() != "aarch64":
   basicBinaries.append( "basic-no-unwind" )

for ex in basicBinaries:
    print("running for '%s'" % ex)
    threads, _ = pstack.JSON(["tests/%s" % ex ])
    assert len(threads) == 1
    thread = threads[0]
    stack = thread["ti_stack"]

    # find the abort frame.
    while not stack[0].get("symbol") or not stack[0]["symbol"]["st_name"].endswith("abort"):
        stack.pop(0)
    stack.pop(0)
    # Assert we get the DIE etc from the g and f functions under abort.
    if "no-unwind" not in ex:
       assert stack[0]["die"] == "g"
       assert stack[1]["die"] == "f"
       assert stack[2]["die"] == "main"
    assert stack[0]["symbol"]["st_name"] == "g"
    assert stack[1]["symbol"]["st_name"] == "f"
    assert stack[2]["symbol"]["st_name"] == "main"
