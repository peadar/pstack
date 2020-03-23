#!/usr/bin/python2

import subprocess
import coremonitor
import pstack

for cmd in [ "tests/segv", 'tests/segvrt' ]:
   pstack_result = pstack.JSON([cmd])
   frames = pstack_result[0]["ti_stack"]

   (trampolines, symbols, dies) = zip(
           *((f["trampoline"],f["symbol"]["st_name"], f["die"]) for f in frames) )
   assert any(trampolines)
   assert "my_abort" in dies
   assert 'f' in dies
   assert 'g' in dies
   assert 'main' in dies
   assert 'raise' in symbols or '__GI_raise' in symbols or 'gsignal' in symbols
