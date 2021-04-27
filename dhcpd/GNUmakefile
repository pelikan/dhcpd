CFLAGS += -Wall -Wextra -Wformat-security -pedantic -std=c99 -g -ggdb3
CFLAGS += -I../compat/include/ -D_DEFAULT_SOURCE -D_XOPEN_SOURCE
CFLAGS += -fstack-protector-strong
LDFLAGS += $(shell pkg-config --libs libbsd-ctor) -levent
FUZZFLAGS = $(CFLAGS) $(LDFLAGS) -lstdc++ -fsanitize-coverage=edge -fsanitize=address -fprofile-arcs -ftest-coverage

OBJS = bpf.o control.o dhcpd.o group.o interface.o lease.o log.o memory.o
OBJS += privsep.o range.o unsatisfied.o Linux.o
OBJS += protocol_input.o protocol_logic.o protocol_output.o protocol_quirks.o
OBJS += ../compat/imsg.o ../compat/imsg-buffer.o ../compat/pidfile.o

dhcpd: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $+

clean:
	$(RM) -- *.o *.gcov *.gcno *.gcda

libFuzzer.a:
	git clone https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer
	clang++ -c -g -O2 -std=c++11 Fuzzer/*.cpp -IFuzzer
	ar ruv $@ Fuzzer*.o
	$(RM) -r -- Fuzzer*.o Fuzzer/

llfuzz_bootp: test/llvm_libfuzzer_bootp_input.c libFuzzer.a
	clang $(FUZZFLAGS) $+ -o $@

llfuzz_dhcp: test/llvm_libfuzzer_dhcp_input.c libFuzzer.a
	clang $(FUZZFLAGS) $+ -o $@
