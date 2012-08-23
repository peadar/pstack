# $FreeBSD$

ELF_BITS ?= 64

PROG=pstack
OBJS += elf.o dwarf.o pstack.o proc_service.o process.o dead.o live.o dump.o

COMPILEFLAGS += \
    -Wno-unused-parameter \
    -Wno-parentheses \
    -g \
    -O0 \
    -DELF_BITS=$(ELF_BITS) \
    -D_GNU_SOURCE \
    -I ../include \
    -Wall \
    -D_FILE_OFFSET_BITS=64 

CFLAGS += -std=c99 $(COMPILEFLAGS)
CXXFLAGS += -std=c++0x $(COMPILEFLAGS)

LIBS += -lthread_db

all: $(PROG) t n

$(PROG): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

t: t.o
	$(CXX) $(LDFLAGS) -o $@ t.o -lpthread

n: n.o
	$(CXX) $(LDFLAGS) -o $@ n.o

n.o: t.cc
	$(CXX) -c $(CXXFLAGS) -DNOTHREADS -o $@ t.cc


clean:
	rm -f $(OBJS) $(PROG) t t.o

ctags:
	ctags --recurse *.c *.cc *.h

depend:
	makedepend *.c *.cc
# DO NOT DELETE

dwarf.o: /usr/include/unistd.h /usr/include/features.h
dwarf.o: /usr/include/bits/predefs.h /usr/include/sys/cdefs.h
dwarf.o: /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h
dwarf.o: /usr/include/gnu/stubs-64.h /usr/include/bits/posix_opt.h
dwarf.o: /usr/include/bits/environments.h /usr/include/bits/types.h
dwarf.o: /usr/include/bits/typesizes.h /usr/include/bits/confname.h
dwarf.o: /usr/include/getopt.h /usr/include/elf.h /usr/include/stdint.h
dwarf.o: /usr/include/bits/wchar.h /usr/include/err.h /usr/include/stdlib.h
dwarf.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
dwarf.o: /usr/include/endian.h /usr/include/bits/endian.h
dwarf.o: /usr/include/bits/byteswap.h /usr/include/sys/types.h
dwarf.o: /usr/include/time.h /usr/include/sys/select.h
dwarf.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
dwarf.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
dwarf.o: /usr/include/bits/pthreadtypes.h /usr/include/alloca.h
dwarf.o: /usr/include/stdio.h /usr/include/libio.h /usr/include/_G_config.h
dwarf.o: /usr/include/wchar.h /usr/include/bits/stdio_lim.h
dwarf.o: /usr/include/bits/sys_errlist.h /usr/include/string.h
dwarf.o: /usr/include/xlocale.h /usr/include/assert.h procinfo.h elfinfo.h
dwarf.o: /usr/include/thread_db.h /usr/include/pthread.h /usr/include/sched.h
dwarf.o: /usr/include/bits/sched.h /usr/include/bits/setjmp.h
dwarf.o: /usr/include/sys/procfs.h /usr/include/sys/time.h
dwarf.o: /usr/include/sys/user.h reader.h dwarf.h /usr/include/sys/ucontext.h
dwarf.o: /usr/include/signal.h /usr/include/bits/signum.h
dwarf.o: /usr/include/bits/siginfo.h /usr/include/bits/sigaction.h
dwarf.o: /usr/include/bits/sigcontext.h /usr/include/bits/sigstack.h
dwarf.o: /usr/include/bits/sigthread.h /usr/include/sys/ptrace.h
dwarf.o: /usr/include/asm/ptrace.h /usr/include/asm/ptrace-abi.h
dwarf.o: /usr/include/linux/types.h /usr/include/asm/types.h
dwarf.o: /usr/include/asm-generic/types.h /usr/include/asm-generic/int-ll64.h
dwarf.o: /usr/include/asm/bitsperlong.h
dwarf.o: /usr/include/asm-generic/bitsperlong.h
dwarf.o: /usr/include/linux/posix_types.h /usr/include/linux/stddef.h
dwarf.o: /usr/include/asm/posix_types.h /usr/include/asm/posix_types_64.h
dwarf.o: /usr/include/asm/processor-flags.h dwarf/tags.h dwarf/forms.h
dwarf.o: dwarf/attr.h dwarf/line_s.h dwarf/line_e.h dwarf/ops.h
dwarf.o: dwarf/archreg.h
elf.o: /usr/include/sys/param.h /usr/include/limits.h /usr/include/features.h
elf.o: /usr/include/bits/predefs.h /usr/include/sys/cdefs.h
elf.o: /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h
elf.o: /usr/include/gnu/stubs-64.h /usr/include/bits/posix1_lim.h
elf.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
elf.o: /usr/include/bits/posix2_lim.h /usr/include/linux/param.h
elf.o: /usr/include/asm/param.h /usr/include/asm-generic/param.h
elf.o: /usr/include/sys/types.h /usr/include/bits/types.h
elf.o: /usr/include/bits/typesizes.h /usr/include/time.h
elf.o: /usr/include/endian.h /usr/include/bits/endian.h
elf.o: /usr/include/bits/byteswap.h /usr/include/sys/select.h
elf.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
elf.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
elf.o: /usr/include/bits/pthreadtypes.h /usr/include/sys/mman.h
elf.o: /usr/include/bits/mman.h /usr/include/sys/procfs.h
elf.o: /usr/include/sys/time.h /usr/include/sys/user.h /usr/include/unistd.h
elf.o: /usr/include/bits/posix_opt.h /usr/include/bits/environments.h
elf.o: /usr/include/bits/confname.h /usr/include/getopt.h
elf.o: /usr/include/sys/stat.h /usr/include/bits/stat.h /usr/include/elf.h
elf.o: /usr/include/stdint.h /usr/include/bits/wchar.h /usr/include/err.h
elf.o: /usr/include/errno.h /usr/include/bits/errno.h
elf.o: /usr/include/linux/errno.h /usr/include/asm/errno.h
elf.o: /usr/include/asm-generic/errno.h /usr/include/asm-generic/errno-base.h
elf.o: /usr/include/fcntl.h /usr/include/bits/fcntl.h /usr/include/stdio.h
elf.o: /usr/include/libio.h /usr/include/_G_config.h /usr/include/wchar.h
elf.o: /usr/include/bits/stdio_lim.h /usr/include/bits/sys_errlist.h
elf.o: /usr/include/stdlib.h /usr/include/bits/waitflags.h
elf.o: /usr/include/bits/waitstatus.h /usr/include/alloca.h
elf.o: /usr/include/string.h /usr/include/xlocale.h elfinfo.h
elf.o: /usr/include/thread_db.h /usr/include/pthread.h /usr/include/sched.h
elf.o: /usr/include/bits/sched.h /usr/include/bits/setjmp.h reader.h dwarf.h
elf.o: /usr/include/sys/ucontext.h /usr/include/signal.h
elf.o: /usr/include/bits/signum.h /usr/include/bits/siginfo.h
elf.o: /usr/include/bits/sigaction.h /usr/include/bits/sigcontext.h
elf.o: /usr/include/bits/sigstack.h /usr/include/bits/sigthread.h
elf.o: /usr/include/sys/ptrace.h /usr/include/asm/ptrace.h
elf.o: /usr/include/asm/ptrace-abi.h /usr/include/linux/types.h
elf.o: /usr/include/asm/types.h /usr/include/asm-generic/types.h
elf.o: /usr/include/asm-generic/int-ll64.h /usr/include/asm/bitsperlong.h
elf.o: /usr/include/asm-generic/bitsperlong.h
elf.o: /usr/include/linux/posix_types.h /usr/include/linux/stddef.h
elf.o: /usr/include/asm/posix_types.h /usr/include/asm/posix_types_64.h
elf.o: /usr/include/asm/processor-flags.h dwarf/tags.h dwarf/forms.h
elf.o: dwarf/attr.h dwarf/line_s.h dwarf/line_e.h dwarf/ops.h
pstack.o: /usr/include/sys/param.h /usr/include/limits.h
pstack.o: /usr/include/features.h /usr/include/bits/predefs.h
pstack.o: /usr/include/sys/cdefs.h /usr/include/bits/wordsize.h
pstack.o: /usr/include/gnu/stubs.h /usr/include/gnu/stubs-64.h
pstack.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
pstack.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
pstack.o: /usr/include/linux/param.h /usr/include/asm/param.h
pstack.o: /usr/include/asm-generic/param.h /usr/include/sys/types.h
pstack.o: /usr/include/bits/types.h /usr/include/bits/typesizes.h
pstack.o: /usr/include/time.h /usr/include/endian.h
pstack.o: /usr/include/bits/endian.h /usr/include/bits/byteswap.h
pstack.o: /usr/include/sys/select.h /usr/include/bits/select.h
pstack.o: /usr/include/bits/sigset.h /usr/include/bits/time.h
pstack.o: /usr/include/sys/sysmacros.h /usr/include/bits/pthreadtypes.h
pstack.o: /usr/include/sys/wait.h /usr/include/signal.h
pstack.o: /usr/include/bits/signum.h /usr/include/bits/siginfo.h
pstack.o: /usr/include/bits/sigaction.h /usr/include/bits/sigcontext.h
pstack.o: /usr/include/bits/sigstack.h /usr/include/sys/ucontext.h
pstack.o: /usr/include/bits/sigthread.h /usr/include/sys/resource.h
pstack.o: /usr/include/bits/resource.h /usr/include/bits/waitflags.h
pstack.o: /usr/include/bits/waitstatus.h /usr/include/sys/time.h
pstack.o: /usr/include/assert.h /usr/include/stdint.h
pstack.o: /usr/include/bits/wchar.h /usr/include/elf.h /usr/include/err.h
pstack.o: /usr/include/errno.h /usr/include/bits/errno.h
pstack.o: /usr/include/linux/errno.h /usr/include/asm/errno.h
pstack.o: /usr/include/asm-generic/errno.h
pstack.o: /usr/include/asm-generic/errno-base.h /usr/include/fcntl.h
pstack.o: /usr/include/bits/fcntl.h /usr/include/bits/stat.h
pstack.o: /usr/include/link.h /usr/include/dlfcn.h /usr/include/bits/dlfcn.h
pstack.o: /usr/include/bits/elfclass.h /usr/include/bits/link.h
pstack.o: /usr/include/stdio.h /usr/include/libio.h /usr/include/_G_config.h
pstack.o: /usr/include/wchar.h /usr/include/bits/stdio_lim.h
pstack.o: /usr/include/bits/sys_errlist.h /usr/include/stdlib.h
pstack.o: /usr/include/alloca.h /usr/include/string.h /usr/include/xlocale.h
pstack.o: /usr/include/sysexits.h /usr/include/unistd.h
pstack.o: /usr/include/bits/posix_opt.h /usr/include/bits/environments.h
pstack.o: /usr/include/bits/confname.h /usr/include/getopt.h
pstack.o: /usr/include/thread_db.h /usr/include/pthread.h
pstack.o: /usr/include/sched.h /usr/include/bits/sched.h
pstack.o: /usr/include/bits/setjmp.h /usr/include/sys/procfs.h
pstack.o: /usr/include/sys/user.h elfinfo.h reader.h procinfo.h dwarf.h
pstack.o: /usr/include/sys/ptrace.h /usr/include/asm/ptrace.h
pstack.o: /usr/include/asm/ptrace-abi.h /usr/include/linux/types.h
pstack.o: /usr/include/asm/types.h /usr/include/asm-generic/types.h
pstack.o: /usr/include/asm-generic/int-ll64.h /usr/include/asm/bitsperlong.h
pstack.o: /usr/include/asm-generic/bitsperlong.h
pstack.o: /usr/include/linux/posix_types.h /usr/include/linux/stddef.h
pstack.o: /usr/include/asm/posix_types.h /usr/include/asm/posix_types_64.h
pstack.o: /usr/include/asm/processor-flags.h dwarf/tags.h dwarf/forms.h
pstack.o: dwarf/attr.h dwarf/line_s.h dwarf/line_e.h dwarf/ops.h
t.o: /usr/include/unistd.h /usr/include/features.h
t.o: /usr/include/bits/predefs.h /usr/include/sys/cdefs.h
t.o: /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h
t.o: /usr/include/gnu/stubs-64.h /usr/include/bits/posix_opt.h
t.o: /usr/include/bits/environments.h /usr/include/bits/types.h
t.o: /usr/include/bits/typesizes.h /usr/include/bits/confname.h
t.o: /usr/include/getopt.h /usr/include/stdlib.h
t.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h
t.o: /usr/include/endian.h /usr/include/bits/endian.h
t.o: /usr/include/bits/byteswap.h /usr/include/sys/types.h
t.o: /usr/include/time.h /usr/include/sys/select.h /usr/include/bits/select.h
t.o: /usr/include/bits/sigset.h /usr/include/bits/time.h
t.o: /usr/include/sys/sysmacros.h /usr/include/bits/pthreadtypes.h
t.o: /usr/include/alloca.h /usr/include/err.h /usr/include/pthread.h
t.o: /usr/include/sched.h /usr/include/bits/sched.h
t.o: /usr/include/bits/setjmp.h
