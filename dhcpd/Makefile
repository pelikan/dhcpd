#	$OpenBSD$

.include <bsd.own.mk>

SRCS=	bpf.c control.c dhcpd.c group.c interface.c lease.c log.c memory.c
SRCS+=	privsep.c range.c unsatisfied.c OpenBSD.c
SRCS+=	protocol_input.c protocol_logic.c protocol_output.c protocol_quirks.c
PROG=	dhcpd

MAN=	dhcpd.8

LDADD+=	-levent -lutil
DPADD+=	${LIBUTIL}

CFLAGS+=	-Wall -Werror -Wextra -pedantic -Wformat-security
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+=	-O3 -std=c99 -g -ggdb3
#CFLAGS+=	-DEBUG_REFCOUNT -DEBUG_IO

.include <bsd.prog.mk>
