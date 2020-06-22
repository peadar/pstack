import json
import subprocess
import coremonitor
import sys

def JSON(cmd, childfunc = None):
    cm = coremonitor.CoreMonitor( cmd, childfunc )
    args = ["./pstack", "-j" ]
    if childfunc:
        args.append(sys.executable)
    args.append(cm.core())
    text = subprocess.check_output(args)
    j = json.loads( text )
    return j

def TEXT(cmd):
    cm = coremonitor.CoreMonitor( cmd, None )
    text = subprocess.check_output(["./pstack", "-a", cm.core()])
    return text
