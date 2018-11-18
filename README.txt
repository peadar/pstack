PSTACK(1)		  BSD General Commands Manual		     PSTACK(1)

NAME
     pstack — print stack traces of threads in a running process or a core
     file

SYNOPSIS
     pstack [-a] [-j] [-n] [-p] [-s] [-t] [-v] [-b seconds] [-g directory]
	    ⟨executable | pid | core⟩ *
     pstack -d elf-file
     pstack -D elf-file
     pstack -V
     pstack -h

DESCRIPTION
     Displays the stack traces of each thread in the running process with
     process id pid or from the core file core

     Normal invocation prints the stack trace from a core file or running
     process. This implementation understands the stack unwinding data in
     eh_frame sections, and properly unwinds through stack frames of code com‐
     piled with -fomit-frame-pointer and on x86_64

     Arguments are as follows.

     -a 	 Show values of arguments passed to functions if possible
		 (requires DWARF debug data for function's code). This also
		 works in python mode.

     -j 	 Use JSON format for the stack output

     -n 	 Do not attempt to find external debug information. DWARF
		 debug information and symbol tables may be contained in sepa‐
		 rate ELF objects, as referenced by either the .gnu_debuglink
		 or inferred by the GNU "build ID" ELF note.

     -p 	 Attempt to print the stack trace from any discovered python
		 interpreters and threads. This feature is experimental, and
		 only works with Python 2.7.

     -s 	 Do not attempt to locate source code information (file and
		 line number) for each frame. Finding the source locations may
		 slow down stack tracing.

     -t 	 Do not use the thread_db library to associate userland thread
		 data structures with kernel level LWPs. For modern linux sys‐
		 tems, LWPs and user mode threads are effectively the same
		 thing. At this point the only benefit of using this library
		 is to associated pthread IDs with the LWPs.

     -v 	 Produce more verbose diagnostics. Can be repeated to increase
		 verbosity further.

     -b N	 Poll-mode: repeatedly trace stacks every N seconds, until
		 interrupted.

     -g directory
		 Use directory as a potential location to find debug ELF
		 images, as referred to by a build-id note or gnu_debuglink
		 section. The default directory is /usr/lib/debug

     ⟨executable | core | pid⟩
		 List of core files or PIDs to trace. An executable image
		 specified on the command line will override the executable
		 derived from the core or processes specified after it until a
		 different executable image is provided

     There are some options to aid debugging issues with ELF and DWARF bina‐
     ries. Namely

     pstack -D ELF-image
		 Format DWARF debugging information of the provided ELF-image
		 in JSON

     pstack -d ELF-image
		 Format ELF information of the provided ELF-image in JSON

     pstack -V	 Print git commit-id used to build pstack

     pstack -h	 Print usage synopsis pstack

SEE ALSO
     procfs(5) ptrace(2)

TODO
     ·	 Support rela for object files

     ·	 This actually works on ARM (i.e., raspi), but needs debug_frame.
	 Apparently, ARM has its own magical sections for storing unwind
	 information that it might be worth implementing.

     ·	 Support inlined subroutines, so we show the surrounding scopes as
	 part
	   of the stack trace.
     works on x86_64 and i686 only.

AUTHORS
     Peter Edwards <peadar (at) isainmdom dot net>

BSD				 Mar 29, 2018				   BSD
