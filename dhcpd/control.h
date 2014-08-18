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

#pragma once
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "dhcp.h"

#define NAME_SIZE	64

/*
 * IPv4 addresses travel in network-byte-order, even though
 * it is mostly local socket.
 */

struct ctl_group {
	char			name[NAME_SIZE];
};

#define	GROUP__CONTROLLER_FLAGS	0xFF
#define	GROUP_WANT_PARENT	0x01
#define	GROUP_WANT_NEXT_SERVER	0x02
#define	GROUP_WANT_FILENAME	0x04
#define	GROUP_WANT_SNAME	0x08

struct ctl_group_settings {
	char			name[NAME_SIZE];
	char			parent[NAME_SIZE];
	u_int32_t		flags;
	struct in_addr		next_server;
	char			sname[BOOTP_SNAME];
	char			filename[BOOTP_FILE];
	u_int8_t		options[1];	/* actually longer */
};

struct ctl_host {
	struct ether_addr	mac;
	struct in_addr		ip;
	char			name[NAME_SIZE];
	char			shared[NAME_SIZE];
	char			group[NAME_SIZE];
};

struct ctl_lease {
	struct ether_addr	mac;
	struct in_addr		ip;
	int			state;
	struct timeval		allocated;
	struct timeval		expires;
	char			shared[NAME_SIZE];
	char			last_hostname[NAME_SIZE];
	char			last_vendor_classid[NAME_SIZE];
};

struct ctl_interface {
	char			name[IF_NAMESIZE];
	unsigned		index;
	char			shared[NAME_SIZE];
};

struct ctl_address {
	struct in_addr		ipv4;
	char			shared[NAME_SIZE];
};

struct ctl_relay {
	struct in_addr		relay;
	struct in_addr		dst;
	char			shared[NAME_SIZE];
};

struct ctl_shared {
	char			name[NAME_SIZE];
	char			group[NAME_SIZE];
};

#define SUBNET__CONTROLLER_FLAGS 0xFF
#define SUBNET_WANT_RANGE	0x01

struct ctl_subnet_settings {
	char			shared[NAME_SIZE];
	struct in_addr		network;
	u_int8_t		prefixlen;
	u_int8_t		delete;
	u_int16_t		flags;
	struct in_addr		range_lo;
	struct in_addr		range_hi;
};

struct ctl_subnet {
	struct in_addr		network;
	u_int8_t		prefixlen;
	char			shared[NAME_SIZE];
	char			group[NAME_SIZE];
};
