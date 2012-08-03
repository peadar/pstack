# $FreeBSD$

ELF_BITS ?= 64

PROG=pstack
OBJS += elf.o dwarf.o pstack.o

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

CFLAGS = -std=c99 $(COMPILEFLAGS)
CXXFLAGS = -std=c++0x $(COMPILEFLAGS)

LIBS += -lthread_db

all: $(PROG) t

$(PROG): $(OBJS)
	$(CXX) -o $@ $(OBJS) $(LIBS)

t: t.o
	$(CXX) -o $@ t.o -lpthread

clean:
	rm -f $(OBJS) $(PROG) tags t t.o

ctags:
	ctags *.c *.h

depend:
	makedepend *.c
