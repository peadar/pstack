#!/usr/bin/python2

import subprocess
import coremonitor
import pstack

for cmd in [ "tests/segv", 'tests/segvrt' ]:
   pstack_result, _ = pstack.JSON([cmd])
   frames = pstack_result[0]["ti_stack"]

   (trampolines, symbols, dies) = zip(
           *((f["trampoline"],
              f["symbol"],
              f["die"]) for f in frames) )

   # convert symbols to extrac their names, and filter out where we have no symbol
   symbols = [ sym["st_name"] for sym in symbols if sym is not None ]
   print(symbols)

   assert any(trampolines)
   assert "my_abort" in dies
   assert 'f' in dies
   assert 'g' in dies
   assert 'main' in dies
   assert 'raise' in symbols or '__GI_raise' in symbols or 'gsignal' in symbols
