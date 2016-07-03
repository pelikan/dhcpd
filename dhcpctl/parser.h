/*	$OpenBSD$ */

/*
 * Copyright (c) 2014 Martin Pelikan <pelikan@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include "dhcpd.h"

enum actions {
	NONE,
	SHELL,

	INTERFACE_ADD,
	INTERFACE_DELETE,
	INTERFACE_LIST,

	ADDRESS_ADD,
	ADDRESS_DELETE,
	ADDRESS_LIST,

	RELAY_ADD,
	RELAY_DELETE,
	RELAY_LIST,

	SHARED_NETWORK_ADD,
	SHARED_NETWORK_DELETE,
	SHARED_NETWORK_LIST,

	SUBNET_ADD,
	SUBNET_DELETE,
	SUBNET_LIST,
	SUBNET_SET,
	SUBNET_SHOW,
	SUBNET_UNSET,

	HOST_ADD,
	HOST_DELETE,

	LEASES_DUMP,
	LEASE_RELEASE,

	GROUP_CREATE,
	GROUP_LIST,
	GROUP_SET,
	GROUP_UNSET,

	STATS,
};

struct parse_result {
	enum actions	 action;
	char		 interface[IF_NAMESIZE];
	char		 group[NAME_SIZE];
	char		 string[NAME_SIZE];
	char		 filename[BOOTP_FILE];
	char		 sname[BOOTP_SNAME];
	struct ether_addr mac;
	char		 syntax[10];
	struct in_addr	 ipv4_1;
	struct in_addr	 ipv4_2;
	struct in_addr	 *ipv4_list;
	size_t		 ipv4_list_cnt;
	struct in_addr	 network;
	u_int32_t	 flags;
	u_int8_t	 prefixlen;

	int		 opt_type;
	int		 opt_length;
	u_int8_t	 opt_value[256];
};

struct parse_result	*parse(int, char *[]);
void			 parse_ip_list(void);
