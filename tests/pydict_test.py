#!/usr/bin/env python3

"""
This test checks whether a python dictionary is printed nicely. The test forks
and in the child process creates a dictionary on the stack and then waits
indefinitely. The parent calls pstack to inspect the child process and asserts
that a neatly printed dictionary is there. Afterwards it sends SIGKILL to the
child and returns.
"""

import signal
import subprocess
import os
import time

import pstack


def main():
    pid = os.fork()
    if pid == 0:
        a_dict = {"ahoy": "sailor"}
        while True:
            time.sleep(1)
    else:
        try:
            # the output is kept raw (in bytes) as python's internal are not
            # exactly UTF-8 only and can make UTF-8 decoder crash
            output = subprocess.check_output(
                ["./" + pstack.PSTACK_BIN, "-pl", str(pid)]
            )
            assert b'"ahoy" : "sailor"' in output
        finally:
            os.kill(pid, signal.SIGKILL)


if __name__ == "__main__":
    main()
