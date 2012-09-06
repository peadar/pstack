# $FreeBSD$

ELF_BITS ?= 64

PROG=pstack
OBJS += elf.o dwarf.o pstack.o proc_service.o process.o dead.o live.o dump.o reader.o

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
	rm -f $(OBJS) $(PROG) t t.o n n.o 

ctags:
	ctags --recurse *.c *.cc *.h

depend:
	true > .depend && makedepend -f .depend $(COMPILEFLAGS) *.c *.cc

ifeq ($(wildcard .depend),.depend)
include .depend
endif
