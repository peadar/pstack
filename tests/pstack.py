import json
import subprocess
import coremonitor
import contextlib
import sys
import os
import tempfile

PSTACK_BIN = os.environ.get("PSTACK_BIN", "pstack")
DO_CORE = os.environ.get("PSTACK_TEST_USECORE", None)

def JSON(cmd):
    args = ["./%s" % PSTACK_BIN, "-j" ]
    if DO_CORE:
        with coremonitor.CoreMonitor(cmd) as cm:
            args.append(scope.core())
            text = subprocess.check_output(args, universal_newlines=True)
            j = json.loads( text )
            return j, None #scope.output
    else:
        fd, fname = tempfile.mkstemp()
        fp = os.fdopen(fd, "r")
        args.append("-o")
        args.append(fname)
        args.append("-x")
        args.append(" ".join(cmd))
        text = subprocess.check_output(args, universal_newlines=True)
        jtext = fp.read()
        j = json.loads( jtext )
        return j, text

def TEXT(cmd):
    with coremonitor.CoreMonitor(cmd) as cm:
        text = subprocess.check_output(["./%s" % PSTACK_BIN, "-a", cm.core()],
                universal_newlines=True)
        return text, cm.output
