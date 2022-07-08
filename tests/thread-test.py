#!/usr/bin/python2

import pstack
import json

threads, text = pstack.JSON(["tests/thread"])
result = json.loads(text)
# we have 10 threads + main
assert len(threads) == 11
entryThreads = 0
for thread in threads:
    assert thread["ti_lid"] in result["lwps"], "LWP %d not in %s" % (thread["ti_lid"], result["lwps"])
    assert thread["ti_tid"] in result["threads"], "thread %d not in %s" % (thread["ti_lid"], result["threads"])
    for frame in thread["ti_stack"]:
        if frame['die'] == 'entry':
            entryThreads += 1
            # the soruce for "entry" should be thread.c
            if not frame['source']:
                print "warning: no source info to test"
            else:
                assert frame['source'][0]['file'].endswith( 'thread.cc' )
                lineNo = frame['source'][0]['line']
                # we should be between unlocking the mutex and pausing
                assert lineNo == result["assert_at"]
assert entryThreads == 10
