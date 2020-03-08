#!/usr/bin/python

import subprocess,json
import coremonitor

cm = coremonitor.CoreMonitor( [ "tests/cpp" ] )
thread = json.loads(subprocess.check_output(["./pstack", "-j", cm.core()]))[0]["ti_stack"]
dies = [ frame["die"] for frame in thread if "die" in frame ]
assert "Foo::Bar::baz" in dies
