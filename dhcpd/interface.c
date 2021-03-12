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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <event.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dhcpd.h"
#include "interface.h"

struct network_interface_tree	ifs_used = RB_INITIALIZER(&ifs_used);
struct network_interface_tree	ifs_nuse = RB_INITIALIZER(&ifs_nuse);
struct network_interface_tree	ifs_want = RB_INITIALIZER(&ifs_want);

struct ipv4_address_tree	ifa_used = RB_INITIALIZER(&ifa_used);
struct ipv4_address_tree	ifa_nuse = RB_INITIALIZER(&ifa_nuse);
struct ipv4_address_tree	ifa_want = RB_INITIALIZER(&ifa_want);

/*
 * Network interface helper functions.
 */
static int
interface_cmp(const struct network_interface *a,
    const struct network_interface *b)
{
	return strncmp(a->name, b->name, sizeof a->name);
}
RB_GENERATE_STATIC(network_interface_tree, network_interface, interfaces,
    interface_cmp)


/*
 * Network address helper functions.
 */
u_int32_t
plen2mask32(u_int8_t plen)
{
	return plen ? ~((1UL << (32 - plen)) - 1) : 0;
}

u_int8_t
mask2plen32(u_int32_t mask)
{
	u_int8_t i;
	mask = ~mask;
	for (i = 0; mask != 0; mask >>= 1, ++i);
	return (32 - i);
}

/*
 * We need that prefixlen for the case of carpdev /24, carp /32.  But we
 * can't do comparison as in subnets, because having overlapping aliases
 * is allowed in the kernel.  Numeric comparison is enough in this case.
 */
static int
ipv4_cmp(const struct network_address *a, const struct network_address *b)
{                                               
	u_int32_t aip = ntohl(a->ipv4.s_addr);
	u_int32_t bip = ntohl(b->ipv4.s_addr);
	int plens = (a->prefixlen < b->prefixlen) ? -1 :
	    ((a->prefixlen == b->prefixlen) ? 0 : 1);

	return (aip < bip) ? -1 : ((aip == bip) ? plens : 1);
}                                                    

RB_GENERATE_STATIC(ipv4_address_tree, network_address, addrs, ipv4_cmp)


/*
 * Network interface database maintenance functions.
 */
ssize_t
interfaces_dump(struct ctl_interface **bufp, ssize_t *lenp)
{
	struct ctl_interface *ctlif = *bufp;
	struct network_interface_tree *tree;
	struct network_interface *ifp;
	ssize_t count = 0;

	tree = &ifs_used;
 again:
	RB_FOREACH(ifp, network_interface_tree, tree) {
		if (*lenp < count + 1) {
			size_t new_count = (count + 1) * 2;

			ctlif = reallocarray(*bufp, new_count, sizeof *ctlif);
			if (ctlif == NULL)
				goto fail;
			*bufp = ctlif;
			*lenp = new_count;

			ctlif += count;
		}
		strlcpy(ctlif->name, ifp->name, sizeof ctlif->name);
		ctlif->index = ifp->index;
		if (ifp->shared)
			strlcpy(ctlif->shared, ifp->shared->name,
			    sizeof ctlif->shared);
		else
			memset(ctlif->shared, 0, sizeof ctlif->shared);

		++count, ++ctlif;
	}

	/* Now export interfaces which aren't in use, but config wants them. */
	if (tree == &ifs_used) {
		tree = &ifs_want;
		goto again;
	}
	return (count);

 fail:
	free(*bufp);
	*bufp = NULL;
	*lenp = 0;
	return (-1L);
}

struct network_interface *
interface_by_name(struct network_interface_tree *tree, const char *name)
{
	struct network_interface fake;

	memset(&fake, 0, sizeof fake);
	strlcpy(fake.name, name, sizeof fake.name);

	return RB_FIND(network_interface_tree, tree, &fake);
}

void
bpf_input(struct network_interface *ni, u_int8_t *data, size_t len)
{
	struct request	 req;
	int		 consumed;

	memset(&req, 0, sizeof req);
	req.rcvd_on_bpf = ni;
	req.shared = ni->shared;

	if ((consumed = ether_input(data, len, &req)) < 0)
		return;

	data += consumed;
	len -= consumed;

	if ((consumed = ipv4_input(data, len, &req)) < 0)
		return;

	data += consumed;
	len -= consumed;

	if ((consumed = udp_input(data, len, &req)) < 0)
		return;

	data += consumed;
	len -= consumed;

	if ((consumed = bootp_input(data, len, &req)) < 0)
		log_info("BPF socket processing went wrong");
}

void
interface_assign_bpf(char *name, int fd)
{
	struct network_interface *ni;

	if ((ni = interface_by_name(&ifs_used, name)) == NULL) {
		close(fd);
		log_warn("closed BPF fd %d for unknown interface %s", fd, name);
		return;
	}

	/* The kernel will tell us how much memory do we need. */
	ni->size = bpf_required_size(fd);

	if ((ni->rbuf = malloc(ni->size)) == NULL) {
		close(fd);
		log_warn("malloc %d bytes, BPF recv buffer", ni->size);
		return;
	}

	ni->fd = fd;
	event_set(&ni->ev, fd, EV_READ | EV_PERSIST, bpf_event, ni);
	if (event_add(&ni->ev, NULL)) {
		close(fd);
		log_warn("event_add(3) BPF read");
		ni->fd = -1;
		free(ni->rbuf);
		ni->rbuf = NULL;
		return;
	}
	log_debug("interface %s: BPF fd %d assigned, %d B", name, fd, ni->size);
}

struct network_interface *
interface_arrived(unsigned idx, const char *name)
{
	struct network_interface *ni;
	struct network_interface_tree *tree;

	/* Does the user want it immediately? */
	if ((ni = interface_by_name(&ifs_want, name)))
		RB_REMOVE(network_interface_tree, &ifs_want, ni);

	/* Sanity check.  We need to know about everything. */
	else if (interface_by_name(&ifs_used, name) ||
	    interface_by_name(&ifs_nuse, name)) {
		log_warnx("interface %s arrived twice", name);
		fatalx("interface database corrupt");
	}

	/* Prepare it to be used soon. */
	if (ni) {
		if (unprivileged_ask_for_bpf(name)) {
			log_warn("%s: can't ask priv child for bpf", __func__);
			return (NULL);
		}
		tree = &ifs_used;
		log_debug("interface %s arrived (configured)", name);
	}

	/* Interface not needed now. */
	else {
		if ((ni = calloc(1, sizeof *ni)) == NULL)
			return (NULL);
		strlcpy(ni->name, name, sizeof ni->name);
		tree = &ifs_nuse;
		log_debug("interface %s arrived (unused)", name);
	}

	ni->fd = -1;
	ni->index = idx;
	RB_INSERT(network_interface_tree, tree, ni);

	return (ni);
}

static void
interface_departure_sanity_checks(struct network_interface *ni)
{
	struct network_address *na;
	char *name = ni->name;

	/* There aren't supposed to be any addresses left. */
	RB_FOREACH(na, ipv4_address_tree, &ifa_used)
		if (na->ni == ni) {
			log_warnx("departing interface %s had running address "
			    "%s/%u in use", name, inet_ntoa(na->ipv4),
			    na->prefixlen);
			fatalx("interface database corrupt");
		}
	RB_FOREACH(na, ipv4_address_tree, &ifa_nuse)
		if (na->ni == ni) {
			log_warnx("departing interface %s had unused address %s"
			    "/%u left", name, inet_ntoa(na->ipv4),
			    na->prefixlen);
			fatalx("interface database corrupt");
		}
}

void
interface_departed(const char *name)
{
	struct network_interface_tree *tree;
	struct network_interface *ni, fake;

	/* Find the interface first. */
	memset(&fake, 0, sizeof fake);
	strlcpy(fake.name, name, sizeof fake.name);

	tree = &ifs_used;
	ni = RB_FIND(network_interface_tree, tree, &fake);
	if (ni == NULL) {
		tree = &ifs_nuse;
		ni = RB_FIND(network_interface_tree, tree, &fake);
	}
	else {
		interface_departure_sanity_checks(ni);
		event_del(&ni->ev);
		RB_REMOVE(network_interface_tree, tree, ni);

		/* Don't forget to close the BPF socket.  But keep the wish. */
		if (close(ni->fd) == -1)
			log_warn("close(2) on a interface fd %d", ni->fd);
		ni->fd = -1;
		ni->index = 0;

		free(ni->rbuf);
		ni->rbuf = NULL;
		ni->size = 0;

		log_info("interface %s departed (wanted)", name);
		RB_INSERT(network_interface_tree, &ifs_want, ni);
		return;
	}

	interface_departure_sanity_checks(ni);
	RB_REMOVE(network_interface_tree, tree, ni);
	log_info("interface %s departed (unused)", name);
	free(ni);
}

char *
interface_add(struct ctl_interface *ctl)
{
	struct network_interface *ni, fake_ni;
	struct shared_network *shared;

	/* Attach it to a shared network. */
	if ((shared = shared_network_find(ctl->shared)) == NULL) {
		log_warnx("can't add interface '%s', no shared network '%s'",
		    ctl->name, ctl->shared);
		return "no such shared_network";
	}

	memset(&fake_ni, 0, sizeof fake_ni);
	strlcpy(fake_ni.name, ctl->name, sizeof fake_ni.name);

	/* Is it already added?  Notify the user. */
	if (RB_FIND(network_interface_tree, &ifs_used, &fake_ni) ||
	    RB_FIND(network_interface_tree, &ifs_want, &fake_ni))
		return "interface already added";

	/* Is it already present in the system?  Plug it into libevent. */
	ni = RB_FIND(network_interface_tree, &ifs_nuse, &fake_ni);
	if (ni) {
		RB_REMOVE(network_interface_tree, &ifs_nuse, ni);
		if (unprivileged_ask_for_bpf(fake_ni.name)) {
			log_warn("%s: can't ask priv child for bpf", __func__);
			return "privileged child not responding";
		}
		ni->shared = shared_network_use(shared);
		RB_INSERT(network_interface_tree, &ifs_used, ni);

		log_debug("interface %s asked for BPF", ni->name);
		return NULL;
	}

	/* Not yet present, add it to the wanted list. */
	if ((ni = calloc(1, sizeof *ni)) == NULL) {
		log_warnx("%s: out of memory", __func__);
		return "out of memory";
	}

	ni->fd = -1;
	strlcpy(ni->name, ctl->name, sizeof ni->name);
	ni->shared = shared_network_use(shared);
	RB_INSERT(network_interface_tree, &ifs_want, ni);

	log_debug("interface %s added for the future", ni->name);
	return NULL;
}

char *
interface_delete(struct ctl_interface *ctl)
{
	struct network_interface_tree *tree;
	struct network_interface *ni, fake;

	memset(&fake, 0, sizeof fake);
	strlcpy(fake.name, ctl->name, sizeof fake.name);

	/* If it is in use, close the BPF socket and add it to dormant list. */
	tree = &ifs_used;
	ni = RB_FIND(network_interface_tree, tree, &fake);
	if (ni) {
		event_del(&ni->ev);
		RB_REMOVE(network_interface_tree, tree, ni);
		if (close(ni->fd) == -1)
			log_warn("close(2) on a interface fd %d", ni->fd);
		ni->fd = -1;
		shared_network_free(ni->shared);
		ni->shared = NULL;

		free(ni->rbuf);
		ni->rbuf = NULL;
		ni->size = 0;

		RB_INSERT(network_interface_tree, &ifs_nuse, ni);

		log_debug("interface %s now not in use", ctl->name);
		return NULL;
	}

	/* Wanted?  Not any more. */
	tree = &ifs_want;
	ni = RB_FIND(network_interface_tree, tree, &fake);
	if (ni) {
		RB_REMOVE(network_interface_tree, tree, ni);
		free(ni);

		log_debug("interface %s deleted", ctl->name);
		return NULL;
	}

	log_warnx("%s: interface %s wasn't wanted", __func__, ctl->name);
	return "no such interface";
}


/*
 * Network IPv4 address database maintenance functions.
 */
struct in_addr
ipv4_addr(void *p)
{
	struct network_address *na = p;

	return na->ipv4;
}

ssize_t
ipv4_addr_dump(struct ctl_address **bufp, ssize_t *lenp)
{
	struct ctl_address *ctla = *bufp;
	struct ipv4_address_tree *tree;
	struct network_address *na;
	ssize_t count = 0;

	tree = &ifa_used;
 again:
	RB_FOREACH(na, ipv4_address_tree, tree) {
		if (*lenp < count + 1) {
			size_t new_count = (count + 1) * 2;

			ctla = reallocarray(*bufp, new_count, sizeof *ctla);
			if (ctla == NULL)
				goto fail;
			*bufp = ctla;
			*lenp = new_count;

			ctla += count;
		}
		ctla->ipv4 = na->ipv4;
		if (na->shared)
			strlcpy(ctla->shared, na->shared->name,
			    sizeof ctla->shared);
		else
			memset(ctla->shared, 0, sizeof ctla->shared);

		++count, ++ctla;
	}

	/* Now export addresses which aren't in use, but config wants them. */
	if (tree == &ifa_used) {
		tree = &ifa_want;
		goto again;
	}
	return (count);

 fail:
	free(*bufp);
	*bufp = NULL;
	*lenp = 0;
	return (-1L);
}

static void
udp_event(int fd, short ev, void *arg)
{
	struct network_address *na = arg;
	struct ip		ip;
	struct sockaddr_in	from;
	socklen_t		fromlen = sizeof from;
	struct request		req;
	u_int8_t		buf[MTU];
	ssize_t			n;

	(void) ev;

	memset(&req, 0, sizeof req);
	req.rcvd_on = arg;
	req.shared = na->shared;
	req.l3 = &ip;
	ip.ip_dst = na->ipv4;

	n = recvfrom(fd, buf, sizeof buf, 0,
	    (struct sockaddr *) &from, &fromlen);
	ip.ip_src = from.sin_addr;

	log_debug_io("UDP read %zd bytes on %s (%s)", n, inet_ntoa(na->ipv4),
	    na->shared->name);

	if (bootp_input(buf, n, &req) < 0)
		log_info("UDP socket procesing went wrong");
}

void
ipv4_addr_assign_udp(u_int32_t *ipv4, int fd)
{
	struct network_address *na, fake;

	memset(&fake, 0, sizeof fake);
	fake.ipv4.s_addr = *ipv4;
	fake.prefixlen = 32;

	na = RB_NFIND(ipv4_address_tree, &ifa_used, &fake);
	if (na == NULL)
		na = RB_MAX(ipv4_address_tree, &ifa_used);

	while (na != NULL) {
		u_int32_t mask = plen2mask32(na->prefixlen);
		u_int32_t masked_net = ntohl(na->ipv4.s_addr) & mask;
		u_int32_t masked_real = ntohl(*ipv4) & mask;

		if (masked_net == masked_real)
			goto assign;
		else if (masked_net < masked_real)
			break;

		na = RB_PREV(ipv4_address_tree, &ifa_used, na);
	}

	close(fd);
	log_warn("closed UDP socket %d, unknown %s", fd, inet_ntoa(fake.ipv4));
	return;

 assign:
	na->fd = fd;
	event_set(&na->ev, fd, EV_READ | EV_PERSIST, udp_event, na);
	if (event_add(&na->ev, NULL)) {
		log_warnx("event_add(3) UDP");
		close(fd);
		na->fd = -1;
		return;
	}
	log_debug("assigned UDP socket %d for %s", fd, inet_ntoa(na->ipv4));
}

struct network_address *
ipv4_addr_arrived(struct network_interface *ni, u_int32_t ipv4, u_int8_t plen)
{
	struct network_address *na, fake;
	struct ipv4_address_tree *tree;

	memset(&fake, 0, sizeof fake);
	fake.ipv4.s_addr = ipv4;
	/* Don't fill in any specific prefix length, wanted addresses have 0. */

	/* Does the user want it immediately? */
	if ((na = RB_NFIND(ipv4_address_tree, &ifa_want, &fake))) {
		if (na->ipv4.s_addr != ipv4)
			goto allocate_new;

		tree = &ifa_used;
		RB_REMOVE(ipv4_address_tree, &ifa_want, na);

		if (unprivileged_ask_for_udp(ipv4)) {
			log_warn("%s: can't ask priv child for udp", __func__);
			return (NULL);
		}
	}

	/* Sanity check.  We need to know about everything. */
	else if ( ((na = RB_NFIND(ipv4_address_tree, &ifa_used, &fake)) &&
	    na->ipv4.s_addr == ipv4) ||
	    ((na = RB_NFIND(ipv4_address_tree, &ifa_nuse, &fake)) &&
	    na->ipv4.s_addr == ipv4) ) {
		log_warnx("IPv4 address 0x%x/%u arrived twice", ipv4, plen);
		fatalx("interface database corrupt");

		/* NOTREACHED older GCC doesn't understand _Noreturn */
		tree = NULL;
	}

	/* This address wasn't wanted. */
	else {
 allocate_new:
		tree = &ifa_nuse;
		if ((na = calloc(1, sizeof *na)) == NULL)
			return (NULL);
	}

	/* Prepare it to be used soon. */
	na->ni = ni;
	na->ipv4.s_addr = ipv4;
	na->prefixlen = plen;

	log_debug("IPv4 address %s arrived", inet_ntoa(na->ipv4));
	RB_INSERT(ipv4_address_tree, tree, na);
	return (na);
}

void
ipv4_addr_departed(u_int32_t ipv4, u_int8_t plen)
{
	struct network_address *na, fake;
	struct ipv4_address_tree *tree;

	memset(&fake, 0, sizeof fake);
	fake.ipv4.s_addr = ipv4;
	fake.prefixlen = plen;

	tree = &ifa_used;
	na = RB_FIND(ipv4_address_tree, tree, &fake);
	if (na == NULL) {
		tree = &ifa_nuse;
		na = RB_FIND(ipv4_address_tree, tree, &fake);
	}
	else {
		event_del(&na->ev);
		RB_REMOVE(ipv4_address_tree, tree, na);
		log_debug("IPv4 address %s departed, keeping",
		    inet_ntoa(na->ipv4));

		/* Don't forget to close the UDP socket.  But keep the wish. */
		close(na->fd);
		na->fd = -1;
		na->ni = NULL;
		na->prefixlen = 0;

		RB_INSERT(ipv4_address_tree, &ifa_want, na);
		return;
	}

	/* Sanity check.  We need to know about everything. */
	if (na == NULL) {
		log_warnx("IPv4 address %#x/%u departed twice", ipv4, plen);
		fatalx("interface database corrupt");
	}

	log_debug("IPv4 address %s departed", inet_ntoa(na->ipv4));
	/* If it wasn't in use, it didn't have any shared_network attached. */
	RB_REMOVE(ipv4_address_tree, tree, na);
	free(na);
}

char *
ipv4_addr_add(struct ctl_address *ctl)
{
	struct network_address *na, fake_na;
	struct shared_network *shared;

	/* Attach it to a shared network. */
	if ((shared = shared_network_find(ctl->shared)) == NULL) {
		log_warnx("can't add address '%s', no shared network '%s'",
		    inet_ntoa(ctl->ipv4), ctl->shared);
		return "no such shared_network";
	}

	memset(&fake_na, 0, sizeof fake_na);
	fake_na.ipv4 = ctl->ipv4;
	/* Don't care about prefixlen, pick the first entry. */

	/* Is it already added?  Notify the user. */
	if (RB_FIND(ipv4_address_tree, &ifa_used, &fake_na) ||
	    RB_FIND(ipv4_address_tree, &ifa_want, &fake_na))
		return "address already added";

	/* Is it already present in the system?  Plug it into libevent. */
	na = RB_NFIND(ipv4_address_tree, &ifa_nuse, &fake_na);
	if (na) {
		if (na->ipv4.s_addr != fake_na.ipv4.s_addr)
			goto notfound;

		RB_REMOVE(ipv4_address_tree, &ifa_nuse, na);
		if (unprivileged_ask_for_udp(na->ipv4.s_addr)) {
			log_warn("%s: can't ask priv child for udp", __func__);
			return "privileged child not responding";
		}
		na->shared = shared_network_use(shared);
		RB_INSERT(ipv4_address_tree, &ifa_used, na);
		RB_INIT(&na->relays);

		log_debug("address %s asked for UDP", inet_ntoa(ctl->ipv4));
		return NULL;
	}

 notfound:
	/* Not yet present, add it to the wanted list. */
	if ((na = calloc(1, sizeof *na)) == NULL) {
		log_warnx("%s: out of memory", __func__);
		return "out of memory";
	}

	na->fd = -1;
	na->ipv4 = fake_na.ipv4;
	na->shared = shared_network_use(shared);
	RB_INSERT(ipv4_address_tree, &ifa_want, na);
	RB_INIT(&na->relays);

	log_debug("address %s added for the future", inet_ntoa(ctl->ipv4));
	return NULL;
}

static void
ipv4_addr_get_rid_of_relays(struct network_address *na)
{
	struct relay *r, *rtemp;

	if ((r = na->relay_any)) {
		na->relay_any = NULL;
		shared_network_free(r->shared);
		free(r);
	}

	RB_FOREACH_SAFE(r, relay_tree, &na->relays, rtemp) {
		RB_REMOVE(relay_tree, &na->relays, r);
		shared_network_free(r->shared);
		free(r);
	}
}

char *
ipv4_addr_delete(struct ctl_address *ctl)
{
	struct ipv4_address_tree *tree;
	struct network_address *na, fake;

	memset(&fake, 0, sizeof fake);
	fake.ipv4 = ctl->ipv4;
	/* Don't care about prefixlen, pick the first entry. */

	/* If it is in use, close the UDP socket and add it to dormant list. */
	tree = &ifa_used;
	na = RB_NFIND(ipv4_address_tree, tree, &fake);
	if (na) {
		if (na->ipv4.s_addr != fake.ipv4.s_addr)
			goto notfound;

		event_del(&na->ev);
		RB_REMOVE(ipv4_address_tree, tree, na);
		if (close(na->fd) == -1)
			log_warn("close(2) on UDP fd %d", na->fd);
		na->fd = -1;
		shared_network_free(na->shared);
		na->shared = NULL;
		RB_INSERT(ipv4_address_tree, &ifa_nuse, na);

		log_debug("address %s now not in use", inet_ntoa(ctl->ipv4));
		return NULL;
	}

 notfound:
	/* Wanted?  Not any more. */
	tree = &ifa_want;
	na = RB_FIND(ipv4_address_tree, tree, &fake);
	if (na) {
		RB_REMOVE(ipv4_address_tree, tree, na);
		shared_network_free(na->shared);
		free(na);

		log_debug("address %s deleted", inet_ntoa(ctl->ipv4));
		return NULL;
	}

	log_warnx("%s: address %s wasn't wanted", __func__,
	    inet_ntoa(ctl->ipv4));
	return "no such address";
}

static struct network_address *
ipv4_addr_find_listener(struct in_addr ip, struct ipv4_address_tree **treep)
{
	struct network_address *na, fake;

	memset(&fake, 0, sizeof fake);
	fake.ipv4 = ip;
	/* Don't care about prefixlen, pick the first entry. */

	*treep = &ifa_used;
 again:
	na = RB_NFIND(ipv4_address_tree, *treep, &fake);
	if (na == NULL || na->ipv4.s_addr != ip.s_addr) {
		if (*treep == &ifa_want)
			return NULL;
		*treep = &ifa_want;
		goto again;
	}
	return (na);
}

void *
bpf_address(struct request *req)
{
	struct network_interface *ni = req->rcvd_on_bpf;
	struct network_address *na, fake;
	struct ipv4_address_tree *tree;

	memset(&fake, 0, sizeof fake);
	fake.ipv4 = req->l3->ip_dst;

	tree = &ifa_used;
 again:
	na = RB_FIND(ipv4_address_tree, tree, &fake);
	if (na == NULL) {
		if (tree == &ifa_nuse)
			goto heuristic;
		tree = &ifa_nuse;
		goto again;
	}

	return (na);

 heuristic:
	/* Return the first IPv4 address on that interface.  Ignore 'alias'. */
	RB_FOREACH(na, ipv4_address_tree, tree) {
		if (na->ni != ni)
			continue;
		return (na);
	}

	if (tree == &ifa_used) {
		struct ether_addr src;
		memcpy(&src, &req->l2->ether_shost, ETHER_ADDR_LEN);

		++stats[STATS_IP_NO_ADDRESS];
		log_warnx("dropping packet from %s to %s on an IPv4-less "
		    "interface %s", ether_ntoa(&src),
		    inet_ntoa(fake.ipv4), ni->name);
		return (NULL);
	}
	/* Maybe there is an UDP-used address we can use here as well. */
	tree = &ifa_used;
	goto heuristic;
}

struct shared_network *
shared_network_from_relay(struct request *req)
{
	struct relay *r, fake;
	struct network_address *na;

	na = req->rcvd_on;
	fake.relay = req->bootp->giaddr;
	r = RB_FIND(relay_tree, &na->relays, &fake);
	if (r)
		return r->shared;
	else if (na->relay_any)
		return na->relay_any->shared;

	return NULL;
}

char *
relay_on(struct ctl_relay *ctl)
{
	struct ipv4_address_tree *tree;
	struct network_address *na;
	struct shared_network *s;
	struct relay *r, fake;

	if ((na = ipv4_addr_find_listener(ctl->dst, &tree)) == NULL)
		return "no such listener";

	if ((s = shared_network_find(ctl->shared)) == NULL)
		return "no such shared_network";

	/* If this is "any" rewrite, reuse the old memory. */
	if (ctl->relay.s_addr == INADDR_ANY && na->relay_any) {
		r = na->relay_any;
		shared_network_free(r->shared);
	}
	else {
		fake.relay = ctl->relay;
		r = RB_FIND(relay_tree, &na->relays, &fake);
		if (r)
			shared_network_free(r->shared);
		else if ((r = calloc(1, sizeof *r)) == NULL)
			return "out of memory";
	}

	r->shared = shared_network_use(s);
	r->relay = ctl->relay;
	if (r->relay.s_addr == INADDR_ANY)
		na->relay_any = r;
	else
		RB_INSERT(relay_tree, &na->relays, r);

	return NULL;
}

char *
relay_off(struct ctl_relay *ctl)
{
	struct ipv4_address_tree *tree;
	struct network_address *na;
	struct relay *r, fake;

	if ((na = ipv4_addr_find_listener(ctl->dst, &tree)) == NULL)
		return "no such listener";

	if (ctl->relay.s_addr == INADDR_ANY)
		r = na->relay_any;
	else {
		fake.relay = ctl->relay;
		r = RB_FIND(relay_tree, &na->relays, &fake);
	}

	if (r == NULL)
		return "no such relay settings";

	shared_network_free(r->shared);

	if (ctl->relay.s_addr == INADDR_ANY)
		na->relay_any = NULL;
	else
		RB_REMOVE(relay_tree, &na->relays, r);

	free(r);

	return NULL;
}

static inline struct ctl_relay *
relay_dump_realloc(struct relay *r, struct ctl_relay **bufp, ssize_t *lenp,
    ssize_t *cntp, struct network_address *na)
{
	struct ctl_relay *ctlr = *bufp + *cntp;

	if (*lenp < *cntp + 1) {
		size_t new_count = (*cntp + 1) * 2;

		ctlr = reallocarray(*bufp, new_count, sizeof *ctlr);
		if (ctlr == NULL)
			return NULL;

		*bufp = ctlr;
		*lenp = new_count;
		ctlr += (*cntp);
	}

	strlcpy(ctlr->shared, r->shared->name, sizeof ctlr->shared);
	ctlr->dst = na->ipv4;
	ctlr->relay = r->relay;

	++(*cntp), ++ctlr;

	return *bufp;
}

static char *
ipv4_addr_relays_dump_one(struct ctl_relay **bufp, ssize_t *lenp, ssize_t *cntp,
    struct network_address *na)
{
	struct relay *r;

	if ((r = na->relay_any))
		if (relay_dump_realloc(r, bufp, lenp, cntp, na) == NULL)
			goto fail;

	RB_FOREACH(r, relay_tree, &na->relays)
		if (relay_dump_realloc(r, bufp, lenp, cntp, na) == NULL)
			goto fail;

	return NULL;
 fail:
	free(*bufp);
	*bufp = NULL;
	*lenp = 0;
	return "out of memory";
}

static char *
ipv4_addr_relays_dump_all(struct ctl_relay **bufp, ssize_t *lenp, ssize_t *cntp)
{
	struct ipv4_address_tree *tree;
	struct network_address *na;
	char *ret = NULL;

	tree = &ifa_used;
 again:
	RB_FOREACH(na, ipv4_address_tree, tree) {
		ret = ipv4_addr_relays_dump_one(bufp, lenp, cntp, na);
		if (ret)
			return (ret);
	}

	if (tree == &ifa_used) {
		tree = &ifa_want;
		goto again;
	}

	return ret;
}

char *
relays_dump(struct ctl_relay **bufp, ssize_t *lenp, ssize_t *countp,
    struct in_addr ip)
{
	struct ipv4_address_tree *tree;
	struct network_address *na;

	if (ip.s_addr != INADDR_ANY) {
		if ((na = ipv4_addr_find_listener(ip, &tree)) == NULL)
			return "no such listener";
		return ipv4_addr_relays_dump_one(bufp, lenp, countp, na);
	}

	return ipv4_addr_relays_dump_all(bufp, lenp, countp);
}


void
interfaces_destroy(void)
{
	struct network_interface *ni, *ni_temp;
	struct network_address *na, *na_temp;

	/* Delete IPv4 addresses with UDP sockets. */
	RB_FOREACH_SAFE(na, ipv4_address_tree, &ifa_used, na_temp) {
		RB_REMOVE(ipv4_address_tree, &ifa_used, na);
		close(na->fd);
		ipv4_addr_get_rid_of_relays(na);
		shared_network_free(na->shared);
		free(na);
	}
	RB_FOREACH_SAFE(na, ipv4_address_tree, &ifa_nuse, na_temp) {
		RB_REMOVE(ipv4_address_tree, &ifa_nuse, na);
		free(na);
	}
	RB_FOREACH_SAFE(na, ipv4_address_tree, &ifa_want, na_temp) {
		RB_REMOVE(ipv4_address_tree, &ifa_want, na);
		ipv4_addr_get_rid_of_relays(na);
		shared_network_free(na->shared);
		free(na);
	}

	/* Delete network interfaces with BPF sockets. */
	RB_FOREACH_SAFE(ni, network_interface_tree, &ifs_used, ni_temp) {
		RB_REMOVE(network_interface_tree, &ifs_used, ni);
		close(ni->fd);
		shared_network_free(ni->shared);
		free(ni->rbuf);
		free(ni);
	}
	RB_FOREACH_SAFE(ni, network_interface_tree, &ifs_nuse, ni_temp) {
		RB_REMOVE(network_interface_tree, &ifs_nuse, ni);
		free(ni);
	}
	RB_FOREACH_SAFE(ni, network_interface_tree, &ifs_want, ni_temp) {
		RB_REMOVE(network_interface_tree, &ifs_want, ni);
		shared_network_free(ni->shared);
		free(ni);
	}
}


/*
 * Output routines.
 */
struct in_addr
destination(struct reply *reply, struct request *req, u_int16_t *l4d)
{
	struct in_addr l3d;

	/*
	 * Pick the destination address, so that the client gets it.
	 * RFC 1542, sections 5.4 for servers and 3.3 for clients.
	 *
	 * Obviously, we pick the first interpretation and treat 'ciaddr'
	 * as something the client is already using and should therefore
	 * be able to receive messages delivered to it.
	 */

	/* The server SHOULD first check the 'ciaddr' field. */
	if (req->bootp->ciaddr.s_addr != INADDR_ANY) {
		/*
		 * RFC 2131 says some DHCPREQUESTs MUST be broadcast anyway.
		 * The BOOTP_FLAG_BROADCAST is copied from (modified) req.
		 */
		if ((req->bootp->giaddr.s_addr == INADDR_ANY) &&
		    (reply->flags & REPLY_BROADCAST_LOCAL))
			l3d.s_addr = INADDR_BROADCAST;
		else
			l3d = req->bootp->ciaddr;
	}

	/* The server SHOULD next check the 'giaddr' field. */
	else if (req->bootp->giaddr.s_addr != INADDR_ANY) {
		l3d = req->bootp->giaddr;
		*l4d = htons(BOOTP_SERVER_PORT);
	}

	/* The server SHOULD examine the newly-defined BROADCAST flag. */
	else if (req->bootp->flags & htons(BOOTP_FLAG_BROADCAST))
		l3d.s_addr = INADDR_BROADCAST;

	else
		l3d = reply->pkt.bootp.yiaddr;

	return l3d;
}

static int
bpf_send(struct network_interface *ni, struct request *req, struct reply *reply)
{
	size_t	pktlen;
	ssize_t	n;

	if (udp_output(reply, req) < 0)
		return (-1);
	if (ipv4_output(reply, req) < 0)
		return (-1);
	if (ether_output(reply, req) < 0)
		return (-1);

	pktlen = sizeof reply->pkt.l2 + sizeof reply->pkt.l3;
	pktlen += sizeof reply->pkt.l4 + sizeof reply->pkt.bootp + reply->off;

	n = write(ni->fd, reply, pktlen);
	if (n == -1) {
		log_warn("write(2) BPF");
		return (-1);
	}
	log_debug_io("BPF sent %zd bytes over %s", n, ni->name);

	return (0);
}

static int
udp_send(struct network_address *na, struct request *req, struct reply *reply)
{
	struct sockaddr_in	from;
	socklen_t		fromlen = sizeof from;
	size_t			len;
	ssize_t			n;

	memset(&from, 0, sizeof from);
	from.sin_family = AF_INET;
	from.sin_port = htons(BOOTP_CLIENT_PORT);
	from.sin_addr = destination(reply, req, &from.sin_port);

	len = sizeof reply->pkt.bootp + reply->off;
	n = sendto(na->fd, &reply->pkt.bootp, len, 0,
	    (struct sockaddr *) &from, fromlen);
	if (n == -1) {
		log_warn("sendto(2) UDP");
		return (-1);
	}
	log_debug_io("UDP sent %zd bytes to %s", n, inet_ntoa(from.sin_addr));

	return (0);
}

int
sendit(struct request *rq, struct reply *rp)
{
	return (rq->rcvd_on_bpf) ?
	    bpf_send(rq->rcvd_on_bpf, rq, rp) : udp_send(rq->rcvd_on, rq, rp);
}
