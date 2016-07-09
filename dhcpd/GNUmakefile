CFLAGS += -Wall -Wextra -pedantic -std=c99 -g -ggdb3
CFLAGS += -I../compat/include/ -D_DEFAULT_SOURCE -D_XOPEN_SOURCE

OBJS = bpf.o control.o dhcpd.o group.o interface.o lease.o log.o memory.o
OBJS += protocol_input.o protocol_logic.o protocol_output.o protocol_quirks.o
OBJS += privsep.o range.o unsatisfied.o Linux.o
OBJS += ../compat/imsg.o ../compat/imsg-buffer.o

dhcpd: $(OBJS)
	$(CC) $(LDFLAGS) $(shell pkg-config --libs libbsd-ctor) -levent -o $@ $+

clean:
	$(RM) *.o
