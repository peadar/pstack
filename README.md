# pstack

`pstack` is a Linux stack-tracing tool for live processes and core files. It reads ELF, DWARF, and call-frame information itself, so it can unwind code compiled without frame pointers and does not depend on GDB. It prints a trace for every thread and can enrich it with symbols, source locations, and—when the target has suitable DWARF—function arguments.

The project also provides a small ELF/DWARF library (`libdwelf`), a process inspection library (`libprocman`), and focused diagnostic tools built on them.

## What it can inspect

- Running Linux processes, by PID
- ELF core files
- Native C and C++ programs, plus other native code with usable DWARF unwind data (such as Go or Rust programs)
- Separate debug files located through `.gnu_debuglink` or GNU build IDs
- Compressed debug sections (zlib and xz)
- Modern CPython processes, including interpreter frames and, with `-l`, local variables

## Quick start

Build and run against a process you are allowed to trace:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
./build/pstack <pid>
```

For a core file, use its path instead:

```sh
./build/pstack /path/to/core
```

`pstack` normally discovers the executable for a live process or core. If it cannot—for example, because a core records only a relative executable path—supply one explicitly:

```sh
./build/pstack -e /path/to/program /path/to/core
# equivalent positional form; this executable applies to later targets
./build/pstack /path/to/program /path/to/core
```

Tracing a live process requires ptrace permission. On many distributions a process may trace its children but not arbitrary same-user processes; container security settings and Yama's `ptrace_scope` can be more restrictive. Run with the appropriate privilege/capability or arrange for the target to be a child of `pstack`.

## Common commands

```sh
# Include function arguments when DWARF describes them
pstack -a <pid-or-core>

# Produce machine-readable output
pstack -j <pid-or-core>

# Trace both the CPython and native stacks
pstack -A <python-pid>

# Print only CPython frames; -l adds Python local variables
pstack -pl <python-pid>

# Trace a command when it stops because of a signal
pstack -x './program --with arguments'

# Sample a process repeatedly, once every 0.5 seconds
pstack -b 0.5 <pid>

# Limit a noisy trace and write it to a file
pstack -M 50 -o trace.txt <pid-or-core>
```

Use `pstack --help` for the complete, authoritative option list. Particularly useful controls include:

| Option | Purpose |
| --- | --- |
| `-s` | Omit source file and line lookup. |
| `-n` | Do not load external debug information. |
| `-g DIR` | Add a directory to the debug-file search path. |
| `--exe-dir DIR` | Add a directory in which to find executables/shared libraries. |
| `--build-id-exepath DIR` / `--build-id-debugpath DIR` | Add build-ID search roots. |
| `--no-buildid` | Disable build-ID lookup. |
| `--clear-search-paths` | Remove the built-in executable and debug search paths. |
| `-R` | Fetch missing build-ID-matched files through `debuginfod`, if `libdebuginfod.so.1` is available at run time. |
| `-d FILE` / `-D FILE` | Emit ELF or DWARF information as JSON and exit. |

You may provide more than one PID or core file in one invocation. Parsing of shared ELF and DWARF data is cached across those targets.

## Debug symbols and output

Unwinding usually needs `.eh_frame`/`.debug_frame` data. Function names, source locations, and argument values improve substantially when matching debug packages are installed. By default, `pstack` searches standard debug locations, follows debug links, and uses build IDs. For binaries copied from another host, provide matching images/debug files with the search-path options above, or use `-R` with a configured debuginfod service.

`-j` produces JSON suitable for scripts. The exact schema is intentionally derived from the current binary; pin the `pstack` version when consuming it in automation. `-a` is best-effort: optimized code, unavailable debug data, and unreadable target memory can prevent an argument from being rendered.

## Building

### Requirements

- CMake 3.10 or newer
- A C++20-capable compiler and standard Linux development tools
- Development packages for zlib and liblzma (for example, `zlib1g-dev` and `liblzma-dev` on Debian/Ubuntu, or `zlib-devel` and `xz-devel` on Fedora/RHEL)

Configure, build, test, and install with CMake:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

The install step installs `pstack`, its man page, libraries and headers, the Python offset data, and selected companion tools. It also makes a best-effort attempt to grant the installed `pstack` `cap_sys_ptrace`; this may fail without the privileges or filesystem support required by `setcap` and is not a build failure.

Useful CMake cache options:

| Option | Default | Effect |
| --- | --- | --- |
| `-DPYRDB=ON` | ON | Build modern CPython remote-debugging support when Python 3 development files are found. |
| `-DLINK_STATIC=ON` | OFF | Link command-line tools to the project's static libraries. |
| `-DPTRACE_TESTS=ON` | OFF | Enable tests that need unrestricted ptrace access. |
| `-DPSTACK_BIN=name` | `pstack` | Choose the installed tracer executable name. |

## CPython support

When built with `PYRDB` support, `pstack -p` finds a compatible CPython interpreter in the target, reads its interpreter and thread frames, and prints Python backtraces. `-A` adds the native DWARF trace; `-l` asks for Python local values, and `-r DEPTH` bounds the nesting depth used while rendering them.

The remote inspector needs an offset-data file matching both the target CPython version and architecture. The repository ships data for supported builds under `pyoff-data/`; installation places it under the platform data directory. For a compatible but unlisted interpreter, generate data from its library and make the resulting `pyoff-*.json` discoverable via the XDG data search path:

```sh
./build/pstack-mkpyoff /path/to/libpython3.so > pyoff-<version>-<arch>.json
```

Run with `-v` to see which offset-data file was selected. CPython internals change frequently, so support is necessarily version-sensitive.

## Other installed tools

- `canal` searches a process or core for references to selected symbols. Its default vtable pattern can help estimate live polymorphic C++ objects.
- `hdmp`, used with the supplied `hdbg` allocator library, reports heap debugger allocation information and the corresponding stacks.
- `pstack-mkpyoff` generates CPython remote-inspection offset data.

`stackusers` is also built for inspecting stack-frame use in ELF images; it is primarily a developer utility and is not installed by the default CMake rules.

## Development

The CTest suite exercises native unwinding, JSON output, compressed debug sections, threading, and Python inspection where the configured environment supports it:

```sh
ctest --test-dir build --output-on-failure
```

Some tests create or trace child processes; enable `PTRACE_TESTS` only in an environment that permits it. The project is BSD-licensed; see [LICENSE](LICENSE).

For the command-line reference installed with the program, see [`pstack.1`](pstack.1). The README describes the current build and operational model; `pstack --help` remains the best source for every option in the binary you have built.
