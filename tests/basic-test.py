#!/usr/bin/python3

import pstack


for ex in [ "basic", "basic-zlib", "basic-zlib-gnu" ]:
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
    assert stack[0]["die"] == "g" and stack[0]["symbol"]["st_name"] == "g"
    assert stack[1]["die"] == "f" and stack[1]["symbol"]["st_name"] == "f"
