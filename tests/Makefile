TESTS: basic-run segv-run thread-run badfp-run
CFLAGS += -g -O0
CXXFLAGS += -g -O0 -std=c++14
LDFLAGS += -g
PSTACK_BIN ?= ../d64/pstack

all: $(TESTS)

basic-run: basic
	-./basic
	$(PSTACK_BIN) -av ./core

segv-run: segv
	-./segv
	$(PSTACK_BIN) -av ./core

badfp-run: badfp
	-./badfp
	$(PSTACK_BIN) -av ./core


thread-run: thread
	-./thread
	$(PSTACK_BIN) -va ./core

basic: basic.o abort.o
	$(CC) -g -o $@ $(LDFLAGS) $^

badfp: badfp.o
	$(CC) -g -o $@ $(LDFLAGS) $^
segv: segv.o abort.o
	$(CC) -g -o $@ $(LDFLAGS) $^
thread: thread.o
	$(CXX) -g -o $@ $(LDFLAGS) $^ -lpthread




clean:
	rm -f core basic *.o segv badfp thread
