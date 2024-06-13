#!/usr/bin/python3

import pstack

data = pstack.dumpJSON(pstack.PSTACK_BIN)
assert len(data) != 0
print( f"pstack binary debug information length is {len(data)}" )
print( f"pstack binary debug information is {data}" )
for ex in [ "basic", "basic-zlib", "basic-zlib-gnu" ]:
    data = pstack.dumpJSON(f"tests/{ex}")
    assert len(data)
