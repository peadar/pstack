# pstack

**A from-scratch implementation of pstack using DWARF debugging and unwind
information.  Works for C/C++, Go, Rust, and Python**

A traditional pstack command can generally print a backtrace of each thread
in a running program, and sometimes from a core file.

This version of pstack uses its own self contained ELF and DWARF parsing
library, `libdwelf` to parse the DWARF debug and unwind information,
to get a stack trace. The functionality is well tested for C++, and is
minimally tested for Go and Rust binaries.  It also supports getting
python language backtraces for cpython.

## Disclaimer
This works for my purposes, and the DWARF parsing library is at least
somewhat useful outside the pstack implementation, but the documentation
is weak. [ctypegen](https://github.com/aristanetworks/ctypegen) is a
good example of a "third party" package that uses libdwelf from here.

## Manpage

There's a manual page, and you can see a text rendering of it
[here](./pstack.1.txt)

## Cheatsheet and Features

### Basic usage
You can generate a stack trace from a running program by using

`pstack <pid>`

For example, you can see what your shell is doing like this
```
bash-5.1$ pstack $$
attaching to live process
process: /proc/532040/mem
thread: 0, lwp: 532040, type: 0
#0  0x00007fde87791aca in __wait4()+26 in /lib64/libc.so.6 at wait4.c:30
#1  0x000055fe8fd610bd in waitchld.constprop.0!()+188 in /usr/bin/bash
#2  0x000055fe8fcc58ea in wait_for!()+1241 in /usr/bin/bash
#3  0x000055fe8fcadd1e in execute_command_internal!()+10029 in /usr/bin/bash
#4  0x000055fe8fcae578 in execute_command!()+199 in /usr/bin/bash
#5  0x000055fe8fc9ff49 in reader_loop!()+648 in /usr/bin/bash
#6  0x000055fe8fc9191e in main!()+5565 in /usr/bin/bash
#7  0x00007fde876ecb75 in __libc_start_main()+212 in /lib64/libc.so.6 at libc-start.c:332
#8  0x000055fe8fc91d1e in _start!()+45 in /usr/bin/bash

bash-5.1$
```
Also, pstack can get traces from core files as easily as it can from
running programs - you can see examples later.


### Argument printing
In the above examples it's obvious that there is debug information
available, as we can see source and line number information. We can also
try and see the values of arguments passed to functions using "-a". This
*requires* debugging information:
```
$ cat t.c
#include <assert.h>
int f(int id, const char*msg) {
   assert(id == 0);
}
int main() {
   f(42, "hello world");
}
$ cc -g -o t t.c
$ ./t
t: t.c:3: f: Assertion `id == 0' failed.
zsh: IOT instruction (core dumped)  ./t
$ ls /var/core
core.t.533472
$ pstack -a /var/core/core.t.533472
process: /var/core/core.t.533472
thread: 0, lwp: 533472, type: 0
#0  0x00007fc0e94482a2 in raise(sig=0x2{r5})+322 in /lib64/libc.so.6 at raise.c:50
#1  0x00007fc0e94318a4 in abort()+277 in /lib64/libc.so.6 at abort.c:79
#2  0x00007fc0e9431789 in __assert_fail_base(fmt=(null), assertion=(null), file=(null), line=(null), function=(null))+14 in /lib64/libc.so.6 at assert.c:92
#3  0x00007fc0e9440a16 in __assert_fail(assertion="id == 0"{r6}, file="t.c"{r12}, line=0x3{r13}, function="f"{r3})+69 in /lib64/libc.so.6 at assert.c:101
#4  0x0000000000401154 in f(id=42, msg="hello world")+45 in ./t at t.c:3
#5  0x000000000040116a in main()+18 in ./t at t.c:6
#6  0x00007fc0e9432b75 in __libc_start_main(main=0x401157, argc=1, argv=0x7ffde5430e38, init=0x7fc0e94482a2{r2}, fini=0{r8}, rtld_fini=0x7ffde5430a40{r9}, stack_end=0x7ffde5430e28)+212 in /lib64/libc.so.6 at libc-start.c:332
#7  0x000000000040106e in _start!()+45 in ./t

$
```

You can see the string and integer arguments on frame 4 and 5 quite
easily, and the format strings from the assertion failure above.


### Other useful arguments

You can pass multiple PIDs and corefiles to pstack, and it will dump
each process in turn. If multiple processes share libraries or images,
then the parsing overhead for DWARF and ELF data only happens once.

You can use `-b` to cause pstack to repeat the trace of a single process
repeatedly with a specified time delay between samples.

pstack will do its best to work out the executable to go with a core file,
but sometimes it can't. For example, if the executable was invoked with
a relative path, that may be all pstack has available to go on. You can
precede the process id/core name with the name of an executable. That
will then be used in preference to anything automatically discovered
until overridden again with a new executable.


### Python

There's also support for getting python backtraces, for both python2
and python3 interpreters. You use '-p' to indicate you are interested
in python backtraces. For example:

```
bash-5.1$ cat test.py
def testme(pid, text, details):
    print("%s: backtrace of %d folows" % (text, pid) )
    os.system("pstack -pa %d" % pid)

import os
testme(os.getpid(), "check", details={'hello': 'there'})
bash-5.1$ python test.py
check: backtrace of 537528 folows
attaching to live process
---- interpreter @55ba07d8a910 -----
pthread: 0x7fc3234c1740, lwp 537528
    testme(537528, "check", {
            "hello" : "there"
        }) in /home/peadar/scm/pstack/test.py:3
    <module>() in /home/peadar/scm/pstack/test.py:6

```

For python, you can even get a full dump of the local frame information
by passing the "-l" option. The output will be very verbose.

## Building

   * To compile, you need CMake, and a compiler that's at least C++20 capable.

   * Various ELF compression mechanisms mean that you should have the
     development package for zlib and xz compression libraries installed. Those
     are known as `liblzma-dev` and `zlib1g-dev` if you are on a
     Debian/Ubuntu-like system, or `xz-devel` and `zlib-devel` on redhat/fedora
     systems

   * If you want python2 support, you need the python2 development headers installed.

   * If you want python3 support, you need the python3 source installed to
     match the distribution of your binary. Currently, things only work with
     python3.9

   * If you want debuginfod support, you need the
     elfutils-debuginfod-client-debuginfo package or equivalent

To build:
```
git clone github.com:peadar/pstack
cd pstack
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
make -j4
```

Python 3 support is disabled by default - in theory, the debug source for your
distro should include the correct source, but at times it may be askew. To
enable, add `-DPYTHON3=ON -DPYTHON3_SOURCE=<path-to-python3>` to the cmake
commandline.  Pay attention to the output of cmake to ensure all the features
you want are enabled.

