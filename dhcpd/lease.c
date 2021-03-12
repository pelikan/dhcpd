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
#include <event.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dhcpd.h"

struct event leases_purger;
struct lease_expiry_tree leases_by_expiration;

int
lease_expiry_cmp(struct lease *a, struct lease *b)
{
	if (timercmp(&a->expires, &b->expires, <))
		return (-1);
	return timercmp(&a->expires, &b->expires, >) ? 1 : 0;
}
int
lease_mac_cmp(struct lease *a, struct lease *b)
{
	return memcmp(&a->mac, &b->mac, ETHER_ADDR_LEN);
}

RB_GENERATE(lease_expiry_tree, lease, leases_by_expiry, lease_expiry_cmp)
RB_GENERATE(lease_mac_tree, lease, leases_by_mac, lease_mac_cmp)

static struct lease *
lease_new_dynamic_subnet(struct subnet *s, struct ether_addr *mac, int valid)
{
	struct range *r;
	int bit;
	struct in_addr a;

	for (r = s->range; r; r = r->next) {
		size_t hosts = (ntohl(r->hi.s_addr) - ntohl(r->lo.s_addr));
		size_t bytes = (hosts + (CHAR_BIT-1)) / CHAR_BIT, i;

		for (i = 0; i < bytes; ++i)
			if (r->freemap[i] != 0xFF)
				break;

		if (i == bytes)
			continue;

		bit = ffs(~r->freemap[i]) - 1;
		a.s_addr = htonl(ntohl(r->lo.s_addr) + (i * CHAR_BIT) + bit);

		/* Last few bits in the freemap can be outside of range. */
		if (range_contains(r, a) == 0)
			continue;
		r->freemap[i] |= (1 << bit);
		return lease_new(s, a, mac, &default_group, valid);
	}
	lease_purger_plan(5);
	return (NULL);
}

struct lease *
lease_new_dynamic(struct request *req, int valid)
{
	struct subnet *n;
	struct lease *l;
	struct ether_addr *mac = &req->bootp->chaddr.ether;

	RB_FOREACH(n, subnet_tree, &req->shared->subnets) {
		if ((l = lease_new_dynamic_subnet(n, mac, valid)))
			return (l);
	}
	return (NULL);
}

struct lease *
lease_previous_dynamic(struct request *req, struct in_addr a)
{
	int byte, bit;
	struct lease *l;
	struct range *r;
	struct subnet *s;
	struct ether_addr *mac = &req->bootp->chaddr.ether;

	if ((s = shared_network_find_subnet(req->shared, a)) == NULL)
		return (NULL);

	for (r = s->range; r; r = r->next)
		if (range_contains(r, a))
			break;

	if (r == NULL)
		return (NULL);

	/*
	 * Might be a good idea to check if it is actually free.
	 * Why didn't we find the lease before?  It may be someone else's.
	 */
	bit = ntohl(a.s_addr) - ntohl(r->lo.s_addr);
	byte = bit / CHAR_BIT;
	bit %= CHAR_BIT;
	if (r->freemap[byte] & (1 << bit)) {
		log_info("%s: address %s seems to be someone else's, not %s",
		    __func__, inet_ntoa(a), ether_ntoa(mac));
		return (NULL);
	}

	l = lease_new(s, a, mac, &default_group, OFFER_LEASE_TIME);
	if (l == NULL)
		return (NULL);
	r->freemap[byte] |= (1 << bit);
	return (l);
}

struct lease *
lease_new(struct subnet *s, struct in_addr a, struct ether_addr *mac,
    struct group *g, int valid)
{
	struct lease *l;
	struct timeval addend = { valid, 0 };

	if ((l = calloc(1, sizeof *l)) == NULL) {
		log_warnx("%s: out of memory", __func__);
		return (NULL);
	}
	l->address = a;

	gettimeofday(&l->allocated, NULL);
	timeradd(&l->allocated, &addend, &l->expires);

	l->subnet = subnet_add_lease(s);
	l->group = group_use(g);
	l->mac = *mac;
	RB_INSERT(lease_expiry_tree, &leases_by_expiration, l);
	RB_INSERT(lease_mac_tree, &s->shared->leases, l);
	shared_network_use(s->shared);

	++stats[STATS_LEASES_PRESENT];
	lease_purger_plan(valid);
	return (l);
}

void
lease_free(struct lease *l)
{
	RB_REMOVE(lease_expiry_tree, &leases_by_expiration, l);
	RB_REMOVE(lease_mac_tree, &l->subnet->shared->leases, l);

	if (l->host)
		l->host->lease = NULL;
	group_free(l->group);
	range_free(l->subnet, l->address);
	subnet_free(l->subnet);
	shared_network_free(l->subnet->shared);
	--stats[STATS_LEASES_PRESENT];

	free(l);
}

static void
leases_purge(int sock, short ev, void *arg)
{
	(void) sock; (void) ev; (void) arg;

	struct lease *l, *tl;
	struct timeval now, next, diff = { DEFAULT_LEASE_TIME, 0 };

	gettimeofday(&now, NULL);
	timeradd(&now, &diff, &next);

	RB_FOREACH_SAFE(l, lease_expiry_tree, &leases_by_expiration, tl)
		if (timercmp(&l->expires, &now, <))
			lease_free(l);
		else
			break;

	if (l && timercmp(&l->expires, &next, <))
		next = l->expires;

	timersub(&next, &now, &diff);
	lease_purger_plan(diff.tv_sec);
}

void
lease_purger_plan(int secs)
{
	/* Wait for another second in case the usecs wrap badly. */
	struct timeval now, tv = { secs + 1, 0 }, old;

	gettimeofday(&now, NULL);

	if (!evtimer_initialized(&leases_purger))
		evtimer_set(&leases_purger, leases_purge, NULL);

	if (evtimer_pending(&leases_purger, &old)) {
		if (old.tv_sec < now.tv_sec + secs)
			return;
		evtimer_del(&leases_purger);
	}

	if (evtimer_add(&leases_purger, &tv))
		log_warnx("leases_purger couldn't get scheduled");
}

/* Store some interesting fields purely for better sysadmin user experience. */
void
lease_whoisit(struct lease *l, struct request *req)
{
	u_int8_t len, *p;

	if ((p = req->dhcp_opts[DHCP_OPT_HOSTNAME])) {
		len = MIN(p[0], sizeof l->last_hostname);
		memcpy(l->last_hostname, p + 1, len);
		memset(l->last_hostname + len, 0,
		    sizeof l->last_hostname - len);
	}
	if ((p = req->dhcp_opts[DHCP_OPT_VENDOR_CLASSID])) {
		len = MIN(p[0], sizeof l->last_vendor_classid);
		memcpy(l->last_vendor_classid, p + 1, len);
		memset(l->last_vendor_classid + len, 0,
		    sizeof l->last_vendor_classid - len);
	}
}

ssize_t
leases_dump(struct ctl_lease **bufp, ssize_t *lenp)
{
	struct ctl_lease *ctll = *bufp;
	struct lease *l;
	ssize_t count = 0;

	RB_FOREACH(l, lease_expiry_tree, &leases_by_expiration) {
		if (*lenp < count + 1) {
			size_t new_count = (count + 1) * 2;

			ctll = reallocarray(*bufp, new_count, sizeof *ctll);
			if (ctll == NULL)
				goto fail;
			*bufp = ctll;
			*lenp = new_count;

			ctll += count;
		}
		strlcpy(ctll->last_hostname, l->last_hostname,
		    sizeof ctll->last_hostname);
		memcpy(ctll->last_vendor_classid, l->last_vendor_classid,
		    sizeof ctll->last_vendor_classid);
		strlcpy(ctll->shared, l->subnet->shared->name,
		    sizeof ctll->shared);
		ctll->state = l->state;
		ctll->allocated = l->allocated;
		ctll->expires = l->expires;
		ctll->ip = l->address;
		ctll->mac = l->mac;

		++count, ++ctll;
	}

	return (count);

 fail:
	free(*bufp);
	*bufp = NULL;
	*lenp = 0;
	return (-1L);
}

struct lease *
lease_find_mac(struct request *req)
{
	struct lease fake;

	memset(&fake, 0, sizeof fake);
	fake.mac = req->bootp->chaddr.ether;
	return RB_FIND(lease_mac_tree, &req->shared->leases, &fake);
}

struct lease *
lease_decline(struct request *req, struct lease *l)
{
	log_info("%s declined %s", ether_ntoa(&l->mac), inet_ntoa(l->address));

	/* Wipe it if we were the one that gave this out to the wrong client. */
	if (memcmp(req->bootp->chaddr.buf, &l->mac, ETHER_ADDR_LEN) == 0) {
		l->state = DECLINED;

		RB_REMOVE(lease_mac_tree, &l->subnet->shared->leases, l);
		memset(&l->mac, 0, sizeof l->mac);
		RB_INSERT(lease_mac_tree, &l->subnet->shared->leases, l);
	}

	return lease_new_dynamic(req, DEFAULT_LEASE_TIME);
}

void
lease_extend(struct reply *r)
{
	struct lease	*l, fake;
	u_int8_t	*p;
	unsigned	 addend;
	struct timeval	 now, diff;

	if ((p = r->options[DHCP_OPT_ADDR_LEASETIME]) == NULL)
		addend = DEFAULT_LEASE_TIME;
	else {
		memcpy(&addend, p + 1, 4);
		addend = ntohl(addend);
	}

	l = r->lease;

	diff.tv_sec = addend + 1;
	diff.tv_usec = arc4random_uniform(1000000);

	gettimeofday(&now, NULL);
	timeradd(&now, &diff, &fake.expires);

	RB_REMOVE(lease_expiry_tree, &leases_by_expiration, l);

	/* Make sure no lease with this precise expiration time exists. */
	while (RB_FIND(lease_expiry_tree, &leases_by_expiration, &fake)) {
		++fake.expires.tv_sec;
		fake.expires.tv_usec = arc4random_uniform(1000000);
	}

	l->expires = fake.expires;
	RB_INSERT(lease_expiry_tree, &leases_by_expiration, l);
	lease_purger_plan(addend);
}

char *
lease_kill(struct ctl_lease *ctl)
{
	struct request	 fake_request;
	struct bootp	 fake_bootp;
	struct lease	*l;

	fake_bootp.chaddr.ether = ctl->mac;
	fake_request.bootp = &fake_bootp;

	if ((fake_request.shared = shared_network_find(ctl->shared)) == NULL)
		return "no such shared network";

	if ((l = lease_find_mac(&fake_request)) == NULL)
		return "no such lease";

	lease_free(l);
	return (NULL);
}
