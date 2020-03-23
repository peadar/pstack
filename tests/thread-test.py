#!/usr/bin/python2

import pstack
threads = pstack.JSON(["tests/thread"])
# we have 10 threads + main
assert len(threads) == 11
entryThreads = 0
for thread in threads:
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
                assert lineNo >= 23 and lineNo <= 24
assert entryThreads == 10
