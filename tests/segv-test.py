#!/usr/bin/python

import os, subprocess
for cmd in [ "tests/segv", 'tests/segvrt' ]:
    os.system(cmd)
    pstack_result = subprocess.check_output(["./pstack", "core"])
    assert 'signal handler called' in pstack_result
    assert 'my_abort' in pstack_result
    assert ' in f' in pstack_result
    assert ' in g' in pstack_result
    assert ' in main' in pstack_result
    assert ' in raise' in pstack_result
    assert ' in my_abort' in pstack_result
