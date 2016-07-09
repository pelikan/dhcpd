/*
 * Copyright (c) 2014 Martin Pelikan <pelikan@storkhole.cz>
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
/*
 * Network interfaces represent potential BPF endpoints where local packets
 * arrive.  The user tells us which ones does she want to listen on and as
 * soon as they arrive in the system, they'll go into the @ifs_used tree.
 * BPF descriptor, once obtained from the privileged child, is added to it.
 *
 * The @ifs_nuse tree stores interfaces the user's not interested in, but
 * already present in the system.  That is, of course, if @want_all_ifs is
 * false.  If we wait for an interface to appear in the future, its struct
 * is waiting on us on @ifs_want.
 *
 * Interfaces in the system arrive and depart, the "wanted" status is added
 * or deleted via the appropriate imsgs.
 */
struct network_interface {
	RB_ENTRY(network_interface)	 interfaces;
	struct shared_network		*shared;
	unsigned	 index;
	char		 name[IF_NAMESIZE];
	u_int8_t	 mac[ETHER_ADDR_LEN];
	int		 oper_state; /* RFC 2863 */

	/* BPF */
	int		 fd;
	struct event	 ev;
	u_int8_t	*rbuf;
	int		 size;
};

RB_HEAD(network_interface_tree, network_interface);
extern struct network_interface_tree	ifs_used;
extern struct network_interface_tree	ifs_nuse;
extern struct network_interface_tree	ifs_want;

/*
 * Network addresses represent potential UDP sockets where either relayed
 * packets from remote networks or local tunnels arrive.  Some addresses
 * are in use (tree @ifa_used), some are just present in the system (tree
 * @ifa_nuse) and some are requested to be served on, but not yet present
 * on any interface (tree @ifa_want).
 *
 * Binding on specific addresses prevents us from having UDP multihoming
 * problems with choosing and filling in the right source address.
 *
 * With an IPv4 address to listen on, the user can optionally specify a
 * shared_network where unrelayed hosts from this fd will be looked for.
 * Relayed packets may set a different shared_network either because an
 * entry in the tree binds that relay to it or the wildcard "relay_any".
 *
 * If, for example, multiple 10.0.0.1's are relaying from two different
 * networks, NAT has to be used to distinguish the UDP socket to which
 * packets from particular parts arrive.  NAT obviously doesn't affect
 * bootp->giaddr but the same relay address can be used differently on
 * different UDP sockets to distinguish these networks.
 */
struct network_address {
	RB_ENTRY(network_address)	 addrs;
	struct network_interface 	*ni;
	struct shared_network		*shared;
	struct relay_tree		 relays;
	struct relay			*relay_any;
	struct in_addr	 ipv4;
	u_int8_t	 prefixlen;

	/* UDP */
	int		 fd;
	struct event	 ev;
};

RB_HEAD(ipv4_address_tree, network_address);
extern struct ipv4_address_tree	ifa_used;
extern struct ipv4_address_tree	ifa_nuse;
extern struct ipv4_address_tree	ifa_want;


/* interface.c */
struct network_interface	*interface_by_name(struct network_interface_tree *, const char *);
struct network_interface	*interface_arrived(unsigned idx, const char *name);
struct network_address		*ipv4_addr_arrived(struct network_interface *, u_int32_t, u_int8_t);

void	 interface_departed(const char *);
void	 ipv4_addr_departed(u_int32_t, u_int8_t);
