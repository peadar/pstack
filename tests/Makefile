TESTS: basic-run segv-run thread-run
CFLAGS += -gdwarf -O0
CXXFLAGS += -gdwarf -O0
LDFLAGS += -gdwarf

all: $(TESTS)

basic-run: basic
	-./basic
	$(PSTACK_BIN) -v ./core

segv-run: segv
	-./segv
	$(PSTACK_BIN) -v ./core

thread-run: thread
	-./thread
	$(PSTACK_BIN) -v ./core

basic: basic.o abort.o
	$(CC) -g -o $@ $(LDFLAGS) $^

segv: segv.o abort.o
	$(CC) -g -o $@ $(LDFLAGS) $^
thread: thread.o
	$(CXX) -g -o $@ $(LDFLAGS) $^ -lpthread




clean:
	rm -f core basic *.o segv
