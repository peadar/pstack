# $FreeBSD$

ELF_BITS ?= 32

PROG=pstack
OBJS += elf.o dwarf.o pstack.o
CFLAGS += \
    -Wno-unused-parameter \
    -Wno-parentheses \
    -g \
    -std=c99 \
    -DELF_BITS=$(ELF_BITS) \
    -D_GNU_SOURCE \
    -D__linux__=1 \
    -I ../include \
    -Wall \
    -D_FILE_OFFSET_BITS=64 

CXXFLAGS += $(CFLAGS)

LIBS += -lthread_db

all: $(PROG) t

$(PROG): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

t: t.o
	$(CXX) -o $@ t.o -lpthread

clean:
	rm -f $(OBJS) $(PROG) tags t t.o

ctags:
	ctags *.c *.h

depend:
	makedepend *.c
# DO NOT DELETE

dwarf.o: /usr/include/unistd.h /usr/include/features.h
dwarf.o: /usr/include/sys/cdefs.h /usr/include/bits/wordsize.h
dwarf.o: /usr/include/gnu/stubs.h /usr/include/gnu/stubs-64.h
dwarf.o: /usr/include/bits/posix_opt.h /usr/include/bits/types.h
dwarf.o: /usr/include/bits/typesizes.h /usr/include/bits/confname.h
dwarf.o: /usr/include/getopt.h /usr/include/elf.h /usr/include/stdint.h
dwarf.o: /usr/include/bits/wchar.h /usr/include/err.h /usr/include/stdlib.h
dwarf.o: /usr/include/sys/types.h /usr/include/time.h /usr/include/endian.h
dwarf.o: /usr/include/bits/endian.h /usr/include/sys/select.h
dwarf.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
dwarf.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
dwarf.o: /usr/include/bits/pthreadtypes.h /usr/include/alloca.h
dwarf.o: /usr/include/stdio.h /usr/include/libio.h /usr/include/_G_config.h
dwarf.o: /usr/include/wchar.h /usr/include/bits/stdio_lim.h
dwarf.o: /usr/include/bits/sys_errlist.h /usr/include/string.h
dwarf.o: /usr/include/assert.h elfinfo.h /usr/include/sys/queue.h
dwarf.o: /usr/include/thread_db.h /usr/include/pthread.h /usr/include/sched.h
dwarf.o: /usr/include/bits/sched.h /usr/include/signal.h
dwarf.o: /usr/include/bits/setjmp.h /usr/include/sys/procfs.h
dwarf.o: /usr/include/sys/time.h /usr/include/sys/user.h dwarf.h
dwarf.o: /usr/include/sys/ucontext.h /usr/include/bits/sigcontext.h
dwarf.o: /usr/include/sys/ptrace.h /usr/include/asm/ptrace.h
dwarf.o: /usr/include/asm/ptrace-abi.h /usr/include/asm/types.h
dwarf.o: /usr/include/asm-generic/int-ll64.h dwarf/tags.h dwarf/forms.h
dwarf.o: dwarf/attr.h dwarf/line_s.h dwarf/line_e.h dwarf/ops.h
dwarf.o: dwarf/archreg.h
elf.o: /usr/include/sys/param.h /usr/include/limits.h /usr/include/features.h
elf.o: /usr/include/sys/cdefs.h /usr/include/bits/wordsize.h
elf.o: /usr/include/gnu/stubs.h /usr/include/gnu/stubs-64.h
elf.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
elf.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
elf.o: /usr/include/linux/param.h /usr/include/asm/param.h
elf.o: /usr/include/sys/types.h /usr/include/bits/types.h
elf.o: /usr/include/bits/typesizes.h /usr/include/time.h
elf.o: /usr/include/endian.h /usr/include/bits/endian.h
elf.o: /usr/include/sys/select.h /usr/include/bits/select.h
elf.o: /usr/include/bits/sigset.h /usr/include/bits/time.h
elf.o: /usr/include/sys/sysmacros.h /usr/include/bits/pthreadtypes.h
elf.o: /usr/include/sys/mman.h /usr/include/bits/mman.h
elf.o: /usr/include/sys/procfs.h /usr/include/sys/time.h
elf.o: /usr/include/sys/user.h /usr/include/unistd.h
elf.o: /usr/include/bits/posix_opt.h /usr/include/bits/confname.h
elf.o: /usr/include/getopt.h /usr/include/sys/stat.h /usr/include/bits/stat.h
elf.o: /usr/include/elf.h /usr/include/stdint.h /usr/include/bits/wchar.h
elf.o: /usr/include/err.h /usr/include/errno.h /usr/include/bits/errno.h
elf.o: /usr/include/linux/errno.h /usr/include/asm/errno.h
elf.o: /usr/include/asm-generic/errno.h /usr/include/asm-generic/errno-base.h
elf.o: /usr/include/fcntl.h /usr/include/bits/fcntl.h /usr/include/stdio.h
elf.o: /usr/include/libio.h /usr/include/_G_config.h /usr/include/wchar.h
elf.o: /usr/include/bits/stdio_lim.h /usr/include/bits/sys_errlist.h
elf.o: /usr/include/stdlib.h /usr/include/alloca.h /usr/include/string.h
elf.o: elfinfo.h /usr/include/sys/queue.h /usr/include/thread_db.h
elf.o: /usr/include/pthread.h /usr/include/sched.h /usr/include/bits/sched.h
elf.o: /usr/include/signal.h /usr/include/bits/setjmp.h dwarf.h
elf.o: /usr/include/sys/ucontext.h /usr/include/bits/sigcontext.h
elf.o: /usr/include/sys/ptrace.h /usr/include/asm/ptrace.h
elf.o: /usr/include/asm/ptrace-abi.h /usr/include/asm/types.h
elf.o: /usr/include/asm-generic/int-ll64.h dwarf/tags.h dwarf/forms.h
elf.o: dwarf/attr.h dwarf/line_s.h dwarf/line_e.h dwarf/ops.h
pstack.o: /usr/include/sys/param.h /usr/include/limits.h
pstack.o: /usr/include/features.h /usr/include/sys/cdefs.h
pstack.o: /usr/include/bits/wordsize.h /usr/include/gnu/stubs.h
pstack.o: /usr/include/gnu/stubs-64.h /usr/include/bits/posix1_lim.h
pstack.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
pstack.o: /usr/include/bits/posix2_lim.h /usr/include/linux/param.h
pstack.o: /usr/include/asm/param.h /usr/include/sys/types.h
pstack.o: /usr/include/bits/types.h /usr/include/bits/typesizes.h
pstack.o: /usr/include/time.h /usr/include/endian.h
pstack.o: /usr/include/bits/endian.h /usr/include/sys/select.h
pstack.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
pstack.o: /usr/include/bits/time.h /usr/include/sys/sysmacros.h
pstack.o: /usr/include/bits/pthreadtypes.h /usr/include/sys/wait.h
pstack.o: /usr/include/signal.h /usr/include/sys/resource.h
pstack.o: /usr/include/bits/resource.h /usr/include/bits/waitflags.h
pstack.o: /usr/include/bits/waitstatus.h /usr/include/bits/siginfo.h
pstack.o: /usr/include/sys/time.h /usr/include/assert.h /usr/include/stdint.h
pstack.o: /usr/include/bits/wchar.h /usr/include/elf.h /usr/include/err.h
pstack.o: /usr/include/errno.h /usr/include/bits/errno.h
pstack.o: /usr/include/linux/errno.h /usr/include/asm/errno.h
pstack.o: /usr/include/asm-generic/errno.h
pstack.o: /usr/include/asm-generic/errno-base.h /usr/include/fcntl.h
pstack.o: /usr/include/bits/fcntl.h /usr/include/link.h /usr/include/dlfcn.h
pstack.o: /usr/include/bits/dlfcn.h /usr/include/bits/elfclass.h
pstack.o: /usr/include/bits/link.h /usr/include/stdio.h /usr/include/libio.h
pstack.o: /usr/include/_G_config.h /usr/include/wchar.h
pstack.o: /usr/include/bits/stdio_lim.h /usr/include/bits/sys_errlist.h
pstack.o: /usr/include/stdlib.h /usr/include/alloca.h /usr/include/string.h
pstack.o: /usr/include/sysexits.h /usr/include/unistd.h
pstack.o: /usr/include/bits/posix_opt.h /usr/include/bits/confname.h
pstack.o: /usr/include/getopt.h /usr/include/thread_db.h
pstack.o: /usr/include/pthread.h /usr/include/sched.h
pstack.o: /usr/include/bits/sched.h /usr/include/bits/setjmp.h
pstack.o: /usr/include/sys/procfs.h /usr/include/sys/user.h elfinfo.h
pstack.o: /usr/include/sys/queue.h dwarf.h /usr/include/sys/ucontext.h
pstack.o: /usr/include/bits/sigcontext.h /usr/include/sys/ptrace.h
pstack.o: /usr/include/asm/ptrace.h /usr/include/asm/ptrace-abi.h
pstack.o: /usr/include/asm/types.h /usr/include/asm-generic/int-ll64.h
pstack.o: dwarf/tags.h dwarf/forms.h dwarf/attr.h dwarf/line_s.h
pstack.o: dwarf/line_e.h dwarf/ops.h
