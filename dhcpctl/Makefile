#	$OpenBSD$

.PATH:		${.CURDIR}/../dhcpd

PROG=		dhcpctl
SRCS=		dhcpctl.c parser.c 

MAN=		dhcpctl.8

LDADD=		-lutil
DPADD+=		${LIBUTIL}

CFLAGS+=	-Wall -Werror -Wextra -pedantic -Wformat-security
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS+=	-std=c99 -g -ggdb3
CFLAGS+=	-I${.CURDIR} -I${.CURDIR}/../dhcpd

.include <bsd.prog.mk>
