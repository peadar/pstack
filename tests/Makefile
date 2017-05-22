TESTS: basic-run segv-run
CFLAGS += -g -O0
LDFLAGS += -g

all: $(TESTS)


basic-run: basic
	-./basic
	../d64/pstack -v ./core


segv-run: segv
	-./segv
	../d64/pstack -v ./core



basic: basic.o abort.o
	$(CC) -o $@ $(LDFLAGS) $^

segv: segv.o abort.o
	$(CC) -o $@ $(LDFLAGS) $^




clean:
	rm -f core basic *.o segv
