#!/usr/bin/python3

import pstack
import json

# We use the "live" strategy here, as that's the only one to support thread
# names
pstack, text = pstack.JSON(["tests/thread", "-w"], strategy="live")
result = json.loads(text)
# Convert the threads list into a map keyed by numeric pthread_t
threads = { thread["pthread_t"]: thread for thread in result["threads"] }

# we have 10 threads + main
assert len(threads) == 11
assert len(pstack) == len(threads)

for pstackThread in pstack:
    expectedThread = threads[pstackThread["ti_tid"]]
    assert expectedThread["name"] == pstackThread["name"]
    assert expectedThread["pthread_t"] == pstackThread["ti_tid"]
    assert expectedThread["lwp"] == pstackThread["ti_lid"]

    for frame in pstackThread["ti_stack"]:
        if frame['die'] == 'entry':
            # the soruce for "entry" should be thread.c
            if not frame['source']:
                print("warning: no source info to test")
            else:
                assert frame['source'][0]['file'].endswith( 'thread.cc' )
                lineNo = frame['source'][0]['line']
                # we should be between unlocking the mutex and pausing
                assert lineNo == result["assert_at"]
