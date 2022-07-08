#!/usr/bin/python2

import pstack
threads, _ = pstack.JSON(["tests/cpp"])
stack = threads[0]["ti_stack"]
dies = [ frame["die"] for frame in stack if "die" in frame ]
assert "Foo::Bar::baz" in dies
