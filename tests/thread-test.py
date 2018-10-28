#!/usr/bin/python

import subprocess,json
import coremonitor
cm = coremonitor.CoreMonitor(["tests/thread"])

pstack_result = subprocess.check_output(["./pstack", "-j", cm.core()])
threads = json.loads(pstack_result)
# we have 10 threads + main
assert len(threads) == 11
entryThreads = 0
for thread in threads:
    for frame in thread["ti_stack"]:
        if frame['function'] == 'entry':
            entryThreads += 1
            # the soruce for "entry" should be thread.c
            if not frame['source']:
                print "warning: no source info to test"
            else:
                assert frame['source'][0]['first'] == 'thread.cc'
                lineNo = frame['source'][0]['second']
                # we should be between unlocking the mutex and pausing
                assert lineNo >= 23 and lineNo <= 24
assert entryThreads == 10

