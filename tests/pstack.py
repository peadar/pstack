import json
import subprocess
import coremonitor
import sys
import os

PSTACK_BIN = os.environ.get("PSTACK_BIN", "pstack")

def JSON(cmd, childfunc = None):
    with coremonitor.CoreMonitor( cmd, childfunc ) as cm:
        args = ["./%s" % PSTACK_BIN, "-j" ]
        if childfunc:
            args.append(sys.executable)
        args.append(cm.core())
        text = subprocess.check_output(args)
        j = json.loads( text )
        return j

def TEXT(cmd):
    with coremonitor.CoreMonitor( cmd, None ) as cm:
        text = subprocess.check_output(["./%s" % PSTACK_BIN, "-a", cm.core()])
        return text
