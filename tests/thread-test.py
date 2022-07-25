#!/usr/bin/python3

import pstack
import json

pstack, text = pstack.JSON(["tests/thread"])
result = json.loads(text)
threads = result["threads"]
lwps = result["lwps"]
assert_at = result["assert_at"]

# we have 10 threads + main
assert len(threads) == 11
for thread in pstack:
    # this will throw an error if the thread or LWP is not in the output for
    # the command, indicating a thread or LWP id from pstack was wrong.
    threads.remove(thread["ti_tid"])
    lwps.remove(thread["ti_lid"])

    for frame in thread["ti_stack"]:
        if frame['die'] == 'entry':
            # the soruce for "entry" should be thread.c
            if not frame['source']:
                print("warning: no source info to test")
            else:
                assert frame['source'][0]['file'].endswith( 'thread.cc' )
                lineNo = frame['source'][0]['line']
                # we should be between unlocking the mutex and pausing
                assert lineNo == assert_at

# When we are finished, pstack should have found all the threads and lwps that
# reported in the output from the command.
assert not lwps
assert not threads
