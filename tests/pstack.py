import json
import signal
import subprocess
import coremonitor
import contextlib
import sys
import os
import tempfile

PSTACK_BIN = os.environ.get("PSTACK_BIN", "pstack")

CORE_STRATEGY = os.environ.get("PSTACK_CORE_STRATEGY", "child")

def _run(cmd, mode, strategy ):
    pstackArgs = ["./%s" % PSTACK_BIN, mode ]
    if strategy == "core":
        with coremonitor.CoreMonitor(cmd) as cm:
            pstackArgs.append(cm.core())
            pstackOutput = subprocess.check_output(pstackArgs, universal_newlines=True)
            return pstackOutput, cm.output
    elif strategy == "child":
        fd, fname = tempfile.mkstemp()
        pstackOutput = os.fdopen(fd, "r")
        pstackArgs.append("-o")
        pstackArgs.append(fname)
        pstackArgs.append("-x")
        pstackArgs.append(" ".join(cmd))
        programOutput = subprocess.check_output(pstackArgs, universal_newlines=True)
        os.remove( fname )
        return pstackOutput.read(), programOutput
    elif strategy == "live":
        with subprocess.Popen( cmd, stdout=subprocess.PIPE) as proc:
            procOutput = proc.stdout.read(1000)
            pstackArgs.append( str( proc.pid ) )
            pstackOutput = subprocess.check_output(pstackArgs, universal_newlines=True)
            os.kill(proc.pid, signal.SIGINT)
            return pstackOutput, procOutput

def TEXT(cmd, strategy=CORE_STRATEGY):
    return _run(cmd, mode="-a", strategy=strategy)

def JSON(cmd, strategy=CORE_STRATEGY):
    pstack, target = _run(cmd, mode="-j", strategy=strategy)
    return json.loads(pstack), target

def dumpJSON(image):
    args = ["./%s" % PSTACK_BIN, "-D", image ]
    pstackOutput = subprocess.check_output(args, universal_newlines=True)
    return json.loads(pstackOutput)
