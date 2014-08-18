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

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "dhcpd.h"
#include "debug.h"

struct shared_network_tree shared_networks;


/*
 * Hosts.
 */
int
host_ipv4_cmp(struct host *a, struct host *b)
{
        u_int32_t aip = ntohl(a->address.s_addr);
        u_int32_t bip = ntohl(b->address.s_addr);
        return (aip < bip) ? -1 : ((aip == bip) ? 0 : 1);
}

int
host_mac_cmp(struct host *a, struct host *b)
{
	return memcmp(&a->mac, &b->mac, ETHER_ADDR_LEN);
}

RB_GENERATE(host_ipv4_tree, host, in_subnet, host_ipv4_cmp)
RB_GENERATE(host_mac_tree, host, in_shared, host_mac_cmp)

char *
host_add(struct ctl_host *ctl_host)
{
	struct host *h;
	struct subnet *s;
	struct group *g;

	if ((g = group_find(ctl_host->group)) == NULL)
		return "no such group";

	if ((s = subnet_find(ctl_host->ip, ctl_host->shared)) == NULL)
		return "no such subnet";

	if ((h = calloc(1, sizeof *h)) == NULL)
		return "out of memory";

	if ((h->name = strndup(ctl_host->name, sizeof ctl_host->name)) == NULL)
		goto fail;
	h->address = ctl_host->ip;
	h->mac = ctl_host->mac;
	h->subnet = s;
	h->group = group_use(g);

	RB_INSERT(host_ipv4_tree, &s->hosts, h);
	RB_INSERT(host_mac_tree, &s->shared->hosts, h);
	return NULL;

 fail:
	free(h);
	return "out of memory";
}

static void
host_delete_one(struct host *h)
{
	if (h->lease)
		h->lease->host = NULL;
	RB_REMOVE(host_ipv4_tree, &h->subnet->hosts, h);
	RB_REMOVE(host_mac_tree, &h->subnet->shared->hosts, h);
	group_free(h->group);
	free(h->name);
	free(h);
}

char *
host_delete(struct ctl_host *ctl_host)
{
	struct host fake, *found;
	struct shared_network *s;
	int deleted = 0;

	memset(&fake, 0, sizeof fake);
	memcpy(&fake.mac, &ctl_host->mac, ETHER_ADDR_LEN);

	RB_FOREACH(s, shared_network_tree, &shared_networks) {
		/* Did the user ask for this specific one? */
		if (ctl_host->shared[0] && strcmp(ctl_host->shared, s->name))
			continue;

		found = RB_FIND(host_mac_tree, &s->hosts, &fake);
		if (found) {
			host_delete_one(found);
			++deleted;
		}
	}
	return deleted ? NULL : "didn't delete anything";
}


/*
 * Relay to address mappings.
 */
int
relay_cmp(struct relay *a, struct relay *b)
{
        u_int32_t aip = ntohl(a->relay.s_addr);
        u_int32_t bip = ntohl(b->relay.s_addr);
        return (aip < bip) ? -1 : ((aip == bip) ? 0 : 1);
}

RB_GENERATE(relay_tree, relay, relays, relay_cmp)


/*
 * Shared networks.
 */
int
shared_network_cmp(struct shared_network *a, struct shared_network *b)
{
	return strcmp(a->name, b->name);
}

RB_GENERATE(shared_network_tree, shared_network, networks, shared_network_cmp)

char *
shared_network_add(struct ctl_shared *ctl)
{
	struct shared_network *s;
	struct group *g;

	if ((g = group_find(ctl->group)) == NULL)
		return "no such group";

	if ((s = shared_network_find(ctl->name)))
		return "shared_network with that name already exists";

	if ((s = malloc(sizeof *s)) == NULL)
		return "out of memory";

	if ((s->name = strndup(ctl->name, sizeof ctl->name)) == NULL)
		goto fail;

	s->refcnt = 1;
	s->group = group_use(g);
	RB_INIT(&s->hosts);
	RB_INIT(&s->leases);
	RB_INIT(&s->subnets);
	RB_INSERT(shared_network_tree, &shared_networks, s);

	log_debug("shared_network '%s' added", s->name);

	return NULL;

 fail:
	free(s);
	return "out of memory";
}

char *
shared_network_delete(struct ctl_shared *shn)
{
	struct shared_network *found;

	if (strcmp(shn->name, "default") == 0)
		return "shared_network 'default' can't be deleted";

	found = shared_network_find(shn->name);
	if (found) {
		if (found->refcnt != 1)
			return "shared_network is still in use";

		RB_REMOVE(shared_network_tree, &shared_networks, found);
		group_free(found->group);

		log_debug("shared_network '%s' deleted", found->name);

		free(found->name);
		free(found);
		return NULL;
	}
	return "didn't delete anything";
}

struct shared_network *
shared_network_find(char *name)
{
	struct shared_network fake;

	fake.name = name;
	return RB_FIND(shared_network_tree, &shared_networks, &fake);
}

int
shared_network_free(struct shared_network *s)
{
	REFCOUNT_DEBUG(s, s->name, s->refcnt);
	--s->refcnt;
	/* These are being deleted explicitly, API is for consistency. */
	return (1);
}

struct host *
shared_network_find_mac(struct request *req)
{
	struct host fake;

	memset(&fake, 0, sizeof fake);
	fake.mac = req->bootp->chaddr.ether;

	return RB_FIND(host_mac_tree, &req->shared->hosts, &fake);
}

struct subnet *
shared_network_find_subnet(struct shared_network *shared, struct in_addr ip)
{
	struct subnet fake_subnet, *subnet;
	u_int32_t found_net, mask;

	memset(&fake_subnet, 0, sizeof fake_subnet);
	fake_subnet.network = ip;
	fake_subnet.prefixlen = 32;
	fake_subnet.shared = shared;

	subnet = RB_NFIND(subnet_tree, &shared->subnets, &fake_subnet);
	if (subnet == NULL)
		subnet = RB_MAX(subnet_tree, &shared->subnets);
	else {
		mask = plen2mask32(subnet->prefixlen);
		found_net = ntohl(subnet->network.s_addr) & mask;
		if ((ntohl(ip.s_addr) & mask) == found_net)
			return (subnet);

		subnet = RB_PREV(subnet_tree, &shared->subnets, subnet);
	}
	if (subnet == NULL)
		return (NULL);

	mask = plen2mask32(subnet->prefixlen);
	found_net = htonl(subnet->network.s_addr) & mask;
	if ((htonl(ip.s_addr) & mask) == found_net)
		return (subnet);
	return (NULL);
}

struct shared_network *
shared_network_use(struct shared_network *s)
{
	REFCOUNT_DEBUG(s, s->name, s->refcnt);
	++s->refcnt;

	return s;
}

/*
 * Subnets.
 */
int
subnet_cmp(struct subnet *a, struct subnet *b)
{
	int x;
	u_int32_t aip, bip;

	if ((x = shared_network_cmp(a->shared, b->shared)) != 0)
		return (x);

	aip = htonl(a->network.s_addr) & plen2mask32(a->prefixlen);
	bip = htonl(b->network.s_addr) & plen2mask32(b->prefixlen);
	return (aip < bip) ? -1 : ((aip == bip) ? 0 : 1);
}

RB_GENERATE(subnet_tree, subnet, subnets, subnet_cmp)

char *
subnet_add(struct ctl_subnet *ctl)
{
	struct shared_network *shared;
	struct subnet *s, fake_subnet;
	struct group *g;
	const u_int32_t mask = plen2mask32(ctl->prefixlen);
	const u_int32_t ourfrst = ntohl(ctl->network.s_addr) & mask;
	const u_int32_t ourlast = ntohl(ctl->network.s_addr) | ~mask;

	if ((g = group_find(ctl->group)) == NULL)
		return "no such group";

	if ((shared = shared_network_find(ctl->shared)) == NULL)
		return "no such shared_network";

	/* Look for overlaps in this shared_network. */
	memset(&fake_subnet, 0, sizeof fake_subnet);
	fake_subnet.shared = shared;
	fake_subnet.network.s_addr = htonl(ourfrst);
	fake_subnet.prefixlen = 32;
	s = RB_NFIND(subnet_tree, &shared->subnets, &fake_subnet);
	if (s) {
		const u_int32_t m = plen2mask32(s->prefixlen);
		const u_int32_t start = ntohl(s->network.s_addr) & m;
		const u_int32_t end = ntohl(s->network.s_addr) | ~m;

		if ((start >= ourfrst && start <= ourlast) ||
		    (end >= ourfrst && end <= ourlast) ||
		    (start <= ourfrst && end >= ourlast))
			return "subnet overlaps with an existing one";
	}

	/* Good to add this subnet in. */
	if ((s = calloc(1, sizeof *s)) == NULL)
		return "out of memory";

	s->refcnt = 1;
	s->network = ctl->network;
	s->prefixlen = ctl->prefixlen;
	s->group = group_use(g);
	s->shared = shared_network_use(shared);

	RB_INIT(&s->hosts);
	RB_INSERT(subnet_tree, &shared->subnets, s);

	log_debug("subnet '%s/%u' added", inet_ntoa(s->network), s->prefixlen);

	return NULL;
}

struct subnet *
subnet_add_lease(struct subnet *s)
{
	REFCOUNT_DEBUG(s, inet_ntoa(s->network), s->refcnt);
	++s->refcnt;

	return s;
}

int
subnet_contains(struct subnet *s, struct in_addr ip)
{
	struct subnet fake;

	fake.shared = s->shared;
	fake.network = ip;
	fake.prefixlen = s->prefixlen;

	return subnet_cmp(s, &fake) == 0;
}

char *
subnet_delete(struct ctl_subnet *ctl)
{
	struct shared_network *shared;
	struct subnet fake, *subnet;

	shared = shared_network_find(ctl->shared);
	if (shared == NULL)
		return "no such shared_network";

	memset(&fake, 0, sizeof fake);
	fake.network = ctl->network;
	fake.prefixlen = ctl->prefixlen;
	fake.shared = shared;

	subnet = RB_FIND(subnet_tree, &shared->subnets, &fake);
	if (subnet) {
		struct host *h, *temph;
		struct in_addr any = { INADDR_ANY }, brd = { INADDR_BROADCAST };

		range_delete(subnet, any, brd);
		log_debug("subnet '%s/%u' deleted", inet_ntoa(subnet->network),
		    subnet->prefixlen);

		subnet->network.s_addr = INADDR_ANY;
		subnet->prefixlen = 0;
		RB_REMOVE(subnet_tree, &shared->subnets, subnet);

		/* Don't leave any host behind, just ticking empty leases. */
		RB_FOREACH_SAFE(h, host_ipv4_tree, &subnet->hosts, temph)
			host_delete_one(h);

		subnet_free(subnet);
		return NULL;
	}
	return "no such subnet";
}

struct subnet *
subnet_find(struct in_addr ip, char *shared_name)
{
	struct shared_network *shared;

	shared = shared_network_find(shared_name);
	if (shared == NULL)
		return (NULL);

	return shared_network_find_subnet(shared, ip);
}

struct host *
subnet_find_host(struct subnet *s, struct in_addr ip)
{
	struct host fake;

	fake.address = ip;
	return RB_FIND(host_ipv4_tree, &s->hosts, &fake);
}

int
subnet_free(struct subnet *s)
{
	REFCOUNT_DEBUG(s, inet_ntoa(s->network), s->refcnt);
	/* Subnets go from their shared_networks' trees explicitly. */
	if (--s->refcnt == 0) {
		if (s->network.s_addr != INADDR_ANY || s->prefixlen)
			fatalx("freeing subnet that's still there!");

		group_free(s->group);
		shared_network_free(s->shared);

		free(s);
		return (0);
	}
	return (s->refcnt);
}

char *
subnet_set(struct ctl_subnet_settings *ctl)
{
	struct subnet *subnet;

	if ((ctl->flags & SUBNET_WANT_RANGE) == 0)
		return "you didn't want RANGE, the only option";

	if ((subnet = subnet_find(ctl->network, ctl->shared)) == NULL)
		return "no such subnet";

	/* The optional high address, if zero, means "until the end". */
	if (ctl->range_hi.s_addr == INADDR_ANY) {
		u_int32_t mask = plen2mask32(subnet->prefixlen);
		u_int32_t hnet = ntohl(subnet->network.s_addr);

		ctl->range_hi.s_addr = htonl(hnet | ~mask);
	}

	if (ntohl(ctl->range_lo.s_addr) > ntohl(ctl->range_hi.s_addr))
		return "addresses in wrong order";

	if (!subnet_contains(subnet, ctl->range_lo) ||
	    !subnet_contains(subnet, ctl->range_hi))
		return "addresses aren't in the subnet";

	return range_add(subnet, ctl->range_lo, ctl->range_hi) < 0 ?
	    "range couldn't be added... overlap?  see syslog." : NULL;
}

char *
subnet_unset(struct ctl_subnet_settings *ctl)
{
	struct subnet *subnet;

	if ((ctl->flags & SUBNET_WANT_RANGE) == 0)
		return "you didn't want RANGE, the only option";

	if ((subnet = subnet_find(ctl->network, ctl->shared)) == NULL)
		return "no such subnet";

	/* The optional high address, if zero, means "until the end". */
	if (ctl->range_hi.s_addr == INADDR_ANY) {
		u_int32_t mask = plen2mask32(subnet->prefixlen);
		u_int32_t hnet = ntohl(subnet->network.s_addr);

		ctl->range_hi.s_addr = htonl(hnet | ~mask);
	}

	if (ntohl(ctl->range_lo.s_addr) > ntohl(ctl->range_hi.s_addr))
		return "addresses in wrong order";

	if (!subnet_contains(subnet, ctl->range_lo) ||
	    !subnet_contains(subnet, ctl->range_hi))
		return "addresses aren't in the subnet";

	range_delete(subnet, ctl->range_lo, ctl->range_hi);

	return (NULL);
}
