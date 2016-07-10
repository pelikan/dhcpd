CFLAGS += -Wall -Wextra -Wformat-security -pedantic -std=c99 -g -ggdb3
CFLAGS += -I../compat/include/ -I../dhcpd/ -D_DEFAULT_SOURCE -D_XOPEN_SOURCE
CFLAGS += -fstack-protector-strong
LDFLAGS += $(shell pkg-config --libs libbsd-ctor)

OBJS = dhcpctl.o parser.o
OBJS += ../compat/imsg.o ../compat/imsg-buffer.o

dhcpctl: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $+

clean:
	$(RM) *.o dhcpctl
