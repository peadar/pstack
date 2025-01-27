#!/usr/bin/env python3

"""
This test checks whether a python dictionary is printed nicely. The test forks
and in the child process creates a dictionary on the stack and then waits
indefinitely. The parent calls pstack to inspect the child process and asserts
that a neatly printed dictionary is there. Afterwards it sends SIGKILL to the
child and returns.
"""

import os
import signal
import subprocess
import time

import pstack


def main():
    # this pipe synchronises the processes, so pstack is launched only
    # after the subprocess actually printed something
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        a_dict = {"ahoy": "sailor"}
        os.write(w, b"written")
        os.close(w)
        while True:
            time.sleep(1)
    else:
        os.close(w)
        os.read(r, 7) # block until we get 7 bytes (the "written" string)
        os.close(r)
        try:
            # the output is kept raw (in bytes), because some of the literals
            # in python code can be interpreted as UTF-8, which breaks the
            # decoder.
            output = subprocess.check_output(
                ["./" + pstack.PSTACK_BIN, "-pl", str(pid)]
            )
            assert b'"ahoy" : "sailor"' in output
        finally:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)

if __name__ == "__main__":
    main()
