import json
import subprocess
import coremonitor
import sys

def JSON(cmd, childfunc = None):
    with coremonitor.CoreMonitor( cmd, childfunc ) as cm:
        args = ["./pstack", "-j" ]
        if childfunc:
            args.append(sys.executable)
        args.append(cm.core())
        text = subprocess.check_output(args)
        j = json.loads( text )
        return j

def TEXT(cmd):
    with coremonitor.CoreMonitor( cmd, None ) as cm:
        text = subprocess.check_output(["./pstack", "-a", cm.core()])
        return text
