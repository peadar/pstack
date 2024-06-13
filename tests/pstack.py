import json
import subprocess
import coremonitor
import contextlib
import sys
import os
import tempfile

PSTACK_BIN = os.environ.get("PSTACK_BIN", "pstack")
DO_CORE = os.environ.get("PSTACK_TEST_USECORE", None)

def _run(cmd, args):
    if DO_CORE:
        with coremonitor.CoreMonitor(cmd) as cm:
            args.append(cm.core())
            pstackOutput = subprocess.check_output(args, universal_newlines=True)
            return pstackOutput, cm.output
    else:
        fd, fname = tempfile.mkstemp()
        pstackOutput = os.fdopen(fd, "r")
        args.append("-o")
        args.append(fname)
        args.append("-x")
        args.append(" ".join(cmd))
        programOutput = subprocess.check_output(args, universal_newlines=True)
        os.remove( fname )
        return pstackOutput.read(), programOutput

def TEXT(cmd):
    return _run(cmd, ["./%s" % PSTACK_BIN, "-a"])

def JSON(cmd):
    pstack, target = _run(cmd, ["./%s" % PSTACK_BIN, "-j" ])
    return json.loads(pstack), target

def dumpJSON(image):
    args = ["./%s" % PSTACK_BIN, "-D", image ]
    pstackOutput = subprocess.check_output(args, universal_newlines=True)
    return json.loads(pstackOutput)
