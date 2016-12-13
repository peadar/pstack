# pstack
Print stack traces of running processes. Uses its own ELF and DWARF parsing.

## installation
You'll need cmake and a C++ compiler. Build/install with cmake. Eg:
<pre>
cd pstack/
mkdir `hostname`
cd `hostname`
cmake ..
make
sudo make install
</pre>

## Overview
This is an implementation of pstack that uses the dwarf unwind tables to do its work.
I wrote it mostly out of curiosity, and maintain it because sometimes its useful.

It also includes "canal", which allows you to analyze objects in the address space,
identifying their types through the stored vptrs, and cross-referencing that with
the vtables found in the symbol table. This can give a quick-and-dirty histogram
of live objects by type for finding memory leaks.
