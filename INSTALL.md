# Installation
You'll need cmake and a C++ compiler. Build/install with cmake. Eg:
<pre>
cd pstack/
cmake .
make
sudo make install
</pre>
Support for various ELF debugging formats requires liblzma and zlib. These
are provided by the liblzma-dev and zlib1g-dev package on .deb systems,
and xz-devel, and zlib-devel on .rpm systems.

If the development packages are not found, the cmake process will generate a warning.

## Python support.
There is rudimentary support for backtracing python processes. If you
have the python 2.7 headers installed, that support is compiled in. At
runtime, you'll need the python debug symbols installed for it to work.

