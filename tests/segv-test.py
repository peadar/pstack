#!/usr/bin/python

import subprocess
import coremonitor

for cmd in [ "tests/segv", 'tests/segvrt' ]:
   cm = coremonitor.CoreMonitor([cmd])
   pstack_result = subprocess.check_output(["./pstack", cm.core()])
   print pstack_result
   assert 'signal handler called' in pstack_result
   assert 'my_abort' in pstack_result
   assert ' in f' in pstack_result
   assert ' in g' in pstack_result
   assert ' in main' in pstack_result
   assert ' in raise' in pstack_result or ' in __GI_raise' in pstack_result
   assert ' in my_abort' in pstack_result
