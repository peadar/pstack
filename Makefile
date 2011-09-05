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
