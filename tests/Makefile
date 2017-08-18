TESTS: basic-run segv-run thread-run
CFLAGS += -g -O0
CXXFLAGS += -g -O0
LDFLAGS += -g

all: $(TESTS)

basic-run: basic
	-./basic
	$(PSTACK_BIN) -av ./core

segv-run: segv
	-./segv
	$(PSTACK_BIN) -av ./core

thread-run: thread
	-./thread
	$(PSTACK_BIN) -va ./core

basic: basic.o abort.o
	$(CC) -g -o $@ $(LDFLAGS) $^

segv: segv.o abort.o
	$(CC) -g -o $@ $(LDFLAGS) $^
thread: thread.o
	$(CXX) -g -o $@ $(LDFLAGS) $^ -lpthread




clean:
	rm -f core basic *.o segv
