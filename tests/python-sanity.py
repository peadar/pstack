#!/usr/bin/env python3

"""Exercise pstack's Python remote-debugging output.

The child deliberately remains in nested Python calls while the parent captures
pstack's output and verifies the frames and representative local values.
"""

import os
from pathlib import Path
import signal
import subprocess
import sys
import pstack


class User:
    def __init__(self):
        self.field = 42
        self.anotherField = "hello world"

class SlottedUser:
    __slots__ = ["a", "b", "c"]

    def __init__(self):
        self.a = 1
        self.b = 2
        self.c = 3


def intermediate_function(n, ready_fd):
    return frame(n, ready_fd)


def frame(n, ready_fd):
    adict = {"twice": n * 2}
    anon_unicode_dict = {2: "twice"}
    astr = "hello world"
    a_non_ascii_str = "hello 😎"
    abytes = b"\x01\x02\x41\xff"
    anone = None
    auser = User()
    atuple = (1, 2, 3)
    alist = ["a", "b", "c"]
    abool = True
    a_short_32_bit_int = 1 << 29
    a_32_bit_int = 1 << 31
    abigint = 1 << 60
    auser_with_a_realized_dict = User()
    auser_with_a_realized_dict.__dict__
    aslotted_user = SlottedUser()

    if n == 1:
        os.write(ready_fd, b"ready")
        signal.pause()
    return intermediate_function(n - 1, ready_fd)


def offset_file(build_dir):
    version = sys.version_info
    version_hex = (version.major << 24) | (version.minor << 16) | (version.micro << 8) | 0xF0
    return build_dir / f"{version_hex:x}.json"

def ensure_offsets(build_dir):
    offsets = offset_file(build_dir)
    if offsets.exists():
        return
    with offsets.open("w") as output:
        print("python version:")
        os.system("python --version")
        os.system("ldd $(which python)")
        print(f"generating offsets from {sys.executable}")
        subprocess.run([build_dir / "pstack-mkpyoff", sys.executable], check=True, stdout=output)

def main(args):
    build_dir = Path.cwd() / ".."

    ensure_offsets(build_dir)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            intermediate_function(2, write_fd)
        finally:
            os._exit(0)

    os.close(write_fd)
    print(f"will trace process {pid}")
    try:
        assert os.read(read_fd, 5) == b"ready"
        output = subprocess.check_output([pstack.PSTACK_PATH, "-pal", str(pid)], cwd=build_dir, text=True)
    finally:
        os.close(read_fd)
        if args.pause:
            sys.stdin.readline()
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)

    expected = (
        f"frame(1, {write_fd}) in ",
        f"intermediate_function(1, {write_fd}) in ",
        "'adict': {'twice': 2}",
        "'anon_unicode_dict': {2: 'twice'}",
        "'astr': 'hello world'",
        "'a_non_ascii_str': 'hello 😎'",
        "'abytes': b'\\x01\\x02A\\xff'",
        "'auser': <User object>",
        "'field': 42",
        "'anotherField': 'hello world'",
        "'atuple': (1, 2, 3)",
        "'alist': ['a', 'b', 'c']",
        "'abool': True",
        "'a_short_32_bit_int': 536870912",
        "'aslotted_user': <SlottedUser object>",
        "{'a': 1, 'b': 2, 'c': 3}",
    )
    for value in expected:
        assert value in output, f"missing {value!r} in pstack output:\n{output}"
    print(f"output from pstack verified ok - {output}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--pause", action="store_true")
    args = parser.parse_args()
    print(f"pause? {args.pause}")
    main(args)
