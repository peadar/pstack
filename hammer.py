import os
import sys
import signal
print(os.getpid())

class User:
    def __init__(self):
        self.field = 42

def frame(n):
    adict = { 'twice' : n * 2 }
    anonUnicodeDict = { 2 : 'twice' }
    astr = "hello world"
    aNonAsciiStr = "hello 😎"
    abytes = b"\x01\x02\x41\xff"
    anone = None
    auser = User()
    atuple = (1,2,3)
    alist = [ 'a', 'b', 'c' ]
    abool = True
    aShort32BitInt = 1 << 29
    a32BitInt = 1 << 31
    abigint = 1 << 60
    print(abigint)
    if n < 2:
        os.system(f"./pstack -p {os.getpid()}")
        print(f"pid {os.getpid()}")
        if args.pause:
            signal.pause()
        if args.gdb:
            os.system(f"gdb -q {sys.executable} {os.getpid()}")
        return 1
    return frame(n-1)

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--pause", "-p", action="store_true")
parser.add_argument("--gdb", "-g", action="store_true")
args = parser.parse_args()
frame(1)
