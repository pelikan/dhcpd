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
#include <stdio.h>
#include <string.h>
#include <vis.h>

#include "dhcpd.h"

/*
 * To simplify expressing the logic, this file assumes some options have been
 * sanitized in protocol_input.c and are either NULL or the correct length.
 */

static int
dhcpoffer(struct request *req, struct lease *l, unsigned flags)
{
	u_int8_t	 msgtype = DHCPOFFER;
	u_int32_t	 netmask = htonl(plen2mask32(l->subnet->prefixlen));
	struct in_addr	 serverid = ipv4_addr(req->rcvd_on);
	struct reply	 reply;

	lease_whoisit(l, req);

	memset(&reply, 0, sizeof reply);
	reply.flags = flags;
	reply.lease = l;

	if (dhcp_output(req, &reply) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_MESSAGE_TYPE, 1, &msgtype) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_SERVER_ID, 4, &serverid.s_addr) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_NETWORK_MASK, 4, &netmask) < 0)
		return (-1);

	if (dhcp_fill_options(req, &reply, l->group) < 0)
		return (-1);

	if (dhcp_add_tlv(&reply, DHCP_OPT_END, 0, NULL) < 0)
		return (-1);

	l->state = OFFERED;
	++stats[STATS_OFFERS];
	log_info("%s: DHCPOFFER: %s -> %s", req->shared->name,
	    ether_ntoa(&req->bootp->chaddr.ether), inet_ntoa(l->address));
	return bootp_output(req, &reply);
}

static int
dhcpack(struct request *req, struct lease *l, unsigned flags)
{
	u_int8_t	 msgtype = DHCPACK;
	u_int32_t	 netmask = htonl(plen2mask32(l->subnet->prefixlen));
	struct reply	 reply;
	struct in_addr	 serverid = ipv4_addr(req->rcvd_on);

	lease_whoisit(l, req);

	memset(&reply, 0, sizeof reply);
	reply.flags = flags | REPLY_EXTEND_LEASE;
	reply.lease = l;

	if (dhcp_output(req, &reply) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_MESSAGE_TYPE, 1, &msgtype) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_SERVER_ID, 4, &serverid.s_addr) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_NETWORK_MASK, 4, &netmask) < 0)
		return (-1);

	if (dhcp_fill_options(req, &reply, l->group) < 0)
		return (-1);

	if (dhcp_add_tlv(&reply, DHCP_OPT_END, 0, NULL) < 0)
		return (-1);

	l->state = ACKED;
	++stats[STATS_ACKS];
	log_info("%s: DHCPACK: %s -> %s", req->shared->name,
	    ether_ntoa(&req->bootp->chaddr.ether), inet_ntoa(l->address));
	return bootp_output(req, &reply);
}

static int
dhcpnak(struct request *req, const char *text)
{
	u_int8_t	 msgtype = DHCPNAK;
	struct reply	 reply;
	struct lease	 fake;
	struct in_addr	 serverid = ipv4_addr(req->rcvd_on);

	memset(&fake, 0, sizeof fake);
	memset(&reply, 0, sizeof reply);
	reply.lease = &fake;

	if (dhcp_output(req, &reply) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_MESSAGE_TYPE, 1, &msgtype) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_SERVER_ID, 4, &serverid.s_addr) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_MESSAGE, strlen(text), text) < 0)
		return (-1);
	if (dhcp_add_tlv(&reply, DHCP_OPT_END, 0, NULL) < 0)
		return (-1);

	/* RFC 2131, server or relay MUST broadcast DHCPNAK messages. */
	req->bootp->flags |= htons(BOOTP_FLAG_BROADCAST);
	reply.flags |= REPLY_BROADCAST_LOCAL;

	++stats[STATS_NAKS];
	log_info("%s: DHCPNAK: %s: %s", req->shared->name,
	    ether_ntoa(&req->bootp->chaddr.ether), text);
	return bootp_output(req, &reply);
}

static char *
preview(struct request *req)
{
	static char x[128];
	char terminated[128];
	int len;
	u_int8_t *p;
	const int max_strlen = sizeof x - 5U;

	if ((p = req->dhcp_opts[DHCP_OPT_HOSTNAME]) == NULL &&
	    (p = req->dhcp_opts[DHCP_OPT_VENDOR_CLASSID]) == NULL)
		return "";

	/* The string may not be NUL-terminated, but strnvis(3) needs it to. */
	len = MIN(max_strlen, p[0]);
	memcpy(terminated, p + 1, len);
	terminated[len] = '\0';
	x[0] = ' ';
	x[1] = '(';
	strnvis(x + 2, terminated, max_strlen, VIS_SAFE);
	strlcat(x, ")", sizeof x);

	return x;
}

static int
not_found(struct request *req, const char *where)
{
	++stats[STATS_DHCP_NOT_FOUND];
	unsatisfied_log(req, where, preview(req));
	return (0);
}

int
dhcpdiscover(struct request *req)
{
	struct host *h;
	struct lease *l;
	unsigned flags = 0;

	/*
	 * RFC 2131, 4.3.1: Try to satisfy whatever the client said she had.
	 */
	if ((l = lease_find_mac(req)))
		goto offer;

	if ((h = shared_network_find_mac(req)) == NULL) {
		if (req->dhcp_opts[DHCP_OPT_ADDR_REQUESTED] == NULL)
			l = lease_new_dynamic(req, OFFER_LEASE_TIME);
		else {
			struct in_addr ip;

			memcpy(&ip, req->dhcp_opts[DHCP_OPT_ADDR_REQUESTED] + 1,
			    sizeof ip);

			/* There should always be a chance if it's taken. */
			if ((l = lease_previous_dynamic(req, ip)) == NULL) {
				l = lease_new_dynamic(req, OFFER_LEASE_TIME);
				flags |= REPLY_BROADCAST_LOCAL;
			}
		}
		if (l == NULL)
			return not_found(req, "DHCPDISCOVER, dynamic");
	}
	else {
		h->lease = l = lease_new(h->subnet, h->address, &h->mac,
		    h->group, OFFER_LEASE_TIME);
		if (l == NULL)
			return not_found(req, "DHCPDISCOVER, static");
		l->host = h;
	}
 offer:
	log_info("%s: DHCPDISCOVER: %s%s", req->shared->name,
	    ether_ntoa(&req->bootp->chaddr.ether), preview(req));
	return dhcpoffer(req, l, flags);
}

static int
dhcp_requested_ip(struct request *req, struct in_addr a)
{
	struct in_addr requested;

	if (req->dhcp_opts[DHCP_OPT_ADDR_REQUESTED] == NULL)
		return (-1);

	memcpy(&requested, req->dhcp_opts[DHCP_OPT_ADDR_REQUESTED] + 1,
	    sizeof requested);

	return (a.s_addr == requested.s_addr) ? 1 : 0;
}

static struct lease *
dhcprequest_unknown_lease(struct request *req)
{
	struct host *h;
	struct in_addr requested;

	/* If this is a static host entry, pretend a DHCPDISCOVER happened. */
	if ((h = shared_network_find_mac(req)) != NULL)
		return lease_new(h->subnet, h->address, &h->mac, h->group,
		    OFFER_LEASE_TIME);

	/* If this belongs to a dynamic range, and is unallocated, fake it. */
	if (req->dhcp_opts[DHCP_OPT_ADDR_REQUESTED] == NULL)
		requested = req->bootp->ciaddr;
	else
		memcpy(&requested, req->dhcp_opts[DHCP_OPT_ADDR_REQUESTED] + 1,
		    sizeof requested);

	return lease_previous_dynamic(req, requested);
}

/* RFC 2131, 4.3.2, REBINDING: we SHOULD check ciaddr for correctness */
static int
dhcprequest_verify_ciaddr(struct request *req, struct lease *l,
    const char *state)
{
	/* Our database must have chaddr and ciaddr paired. */
	if (req->bootp->ciaddr.s_addr != l->address.s_addr) {
		char want[INET_ADDRSTRLEN];
		strlcpy(want, inet_ntoa(l->address), sizeof want);

		log_info("%s: %s, chaddr %s asked for %s, we only have %s",
		    __func__, state, ether_ntoa(&req->bootp->chaddr.ether),
		    inet_ntoa(req->bootp->ciaddr), want);

		/*
		 * RFC 1542 section 5.4 says non-zero ciaddr means trusting the
		 * field and sending any responses there, bypassing any relays.
		 * In this case we need to send a DHCPNAK which needs broadcast
		 * or delivered directly to chaddr, in order to be heard by the
		 * client.  So clobber the address so that downstream code puts
		 * either broadcast or giaddr into the destination field.
		 *
		 * Furthermore, RFC 2131, table 3 says that DHCPNAKs will have
		 * ciaddr+yiaddr set to 0, so this is the correct thing to do.
		 */
		req->bootp->ciaddr.s_addr = INADDR_ANY;
		return (-1);
	}
	return (0);
}

/* RFC 2131, 4.3.2, RENEWING wants the server to trust ciaddr. */
static int
dhcprequest_renewing_checks(struct request *req, struct lease *l)
{
	/* dnsmasq unicasts renew for wifi and kernel sends it over wired eth */
	if (req->l3->ip_src.s_addr != req->bootp->ciaddr.s_addr) {
		char l3src[INET_ADDRSTRLEN];
		strlcpy(l3src, inet_ntoa(req->l3->ip_src),
		    sizeof l3src);

		log_info("%s: IPv4 source %s != BOOTP ciaddr %s: "
		    "NAT or multiple connected interfaces?",
		    __func__, l3src, inet_ntoa(req->bootp->ciaddr));
	}

	return dhcprequest_verify_ciaddr(req, l, "RENEWING");
}

int
dhcprequest(struct request *req)
{
	struct lease *l;
	unsigned flags = 0;
	const char *state = "RENEWING";

	l = lease_find_mac(req);

	/*
	 * RFC 2131, section 4.3.2, INIT-REBOOT, RENEWING and REBINDING state
	 */
	if (req->dhcp_opts[DHCP_OPT_SERVER_ID] == NULL) {
		/* Try to make up whatever she had previously. */
		if (l == NULL && (l = dhcprequest_unknown_lease(req)) == NULL)
			goto notfound;

		/*
		 * INIT-REBOOT or REBINDING and 'the notion of previous addr'.
		 * In both cases, the DHCPACK MUST be broadcast, because these
		 * states could mean problems on the network.
		 */
		if (req->l3->ip_dst.s_addr == INADDR_BROADCAST ||
		    (req->bootp->giaddr.s_addr &&
		    req->l3->ip_src.s_addr == req->bootp->giaddr.s_addr)) {
			req->bootp->flags |= htons(BOOTP_FLAG_BROADCAST);
			flags |= REPLY_BROADCAST_LOCAL;

			switch (dhcp_requested_ip(req, l->address)) {
			case (1):
				state = "INIT-REBOOT";
				++stats[STATS_REQUESTS_INIT_REBOOT];
				if (req->bootp->ciaddr.s_addr != INADDR_ANY)
					goto invalid;
				break;

			case (-1):
				state = "REBINDING";
				++stats[STATS_REQUESTS_REBINDING];
				if (req->bootp->ciaddr.s_addr == INADDR_ANY)
					goto invalid;
				if (dhcprequest_verify_ciaddr(req, l, state))
					goto invalid;
				break;

			case (0):
				++stats[STATS_REQUESTS_INIT_REBOOT];
				log_info("%s: DHCPREQUEST INIT-REBOOT: %s%s "
				    "didn't request IP %s", req->shared->name,
				    ether_ntoa(&req->bootp->chaddr.ether),
				    preview(req), inet_ntoa(l->address));
				return dhcpnak(req, "lease has a different IP");
			}
		}
		/*
		 * RENEWING is unicast without using relays, most common case.
		 */
		else {
			if (dhcprequest_renewing_checks(req, l))
				return (-1);
			++stats[STATS_REQUESTS_RENEWING];
		}
		log_info("%s: DHCPREQUEST %s: %s%s", req->shared->name,
		    state, ether_ntoa(&req->bootp->chaddr.ether), preview(req));
	}
	/* SELECTING state means previously OFFERed yiaddr in the option. */
	else {
		if (l == NULL)
			goto notfound;

		++stats[STATS_REQUESTS_SELECTING];
		log_info("%s: DHCPREQUEST SELECTING: %s%s", req->shared->name,
		    ether_ntoa(&req->bootp->chaddr.ether), preview(req));

		switch (dhcp_requested_ip(req, l->address)) {
		case (0):
			log_info("%s: SELECTING different requested IP than %s",
			    __func__, inet_ntoa(l->address));
			return dhcpnak(req, "lease has a different IP");
		case (-1):
			log_info("%s: no requested IP in SELECTING", __func__);
			return dhcpnak(req, "no requested IP in SELECTING");
		}

		if (l->state != OFFERED)
			log_debug("%s assumed SELECTING with lease in state %d",
			    ether_ntoa(&req->bootp->chaddr.ether), l->state);
	}

	return dhcpack(req, l, flags);

 invalid:
	log_info("%s: DHCPREQUEST %s (invalid): %s%s", req->shared->name,
	    state, ether_ntoa(&req->bootp->chaddr.ether), preview(req));
	return dhcpnak(req, "invalid BOOTREQUEST packet, see RFC 2131");

 notfound:
	not_found(req, "DHCPREQUEST");
	return dhcpnak(req, "your MAC address wasn't found in our database");
}

int
dhcpdecline(struct request *req)
{
	struct lease *l;

	log_info("%s: DHCPDECLINE: %s%s", req->shared->name,
	    ether_ntoa(&req->bootp->chaddr.ether), preview(req));

	if ((l = lease_find_mac(req))) {
		if ((l = lease_decline(req, l)) == NULL)
			return not_found(req, "DHCPDECLINE, new try");
		return dhcpack(req, l, 0);
	}
	return not_found(req, "DHCPDECLINE");
}

int
dhcprelease(struct request *req)
{
	struct lease *l;

	/*
	 * XXX We might want to do more checks before letting attackers
	 * XXX just killing valid leases remotely.  Any ideas what these
	 * XXX checks should look like?  Same applies for DHCPDECLINE.
	 * XXX Level 2:  Do these checks apply when the client is relayed?
	 */
	if ((l = lease_find_mac(req))) {
		log_info("releasing lease %s", inet_ntoa(l->address));
		lease_free(l);
	}

	log_info("%s: DHCPRELEASE: %s %s%s", req->shared->name,
	    l ? "released" : "no lease for",
	    ether_ntoa(&req->bootp->chaddr.ether), preview(req));
	return (0);
}

int
dhcpinform(struct request *req)
{
	struct in_addr ip = req->bootp->ciaddr;
	struct lease fake_lease;

	memset(&fake_lease, 0, sizeof fake_lease);
	fake_lease.subnet = shared_network_find_subnet(req->shared, ip);
	if (fake_lease.subnet == NULL)
		return not_found(req, "DHCPINFORM");

	fake_lease.host = subnet_find_host(fake_lease.subnet, ip);
	fake_lease.address = req->bootp->ciaddr;
	fake_lease.group = &default_group;

	log_info("%s: DHCPINFORM: %s about %s%s", req->shared->name,
	    ether_ntoa(&req->bootp->chaddr.ether),
	    inet_ntoa(fake_lease.address), preview(req));
	return dhcpack(req, &fake_lease, REPLY_TO_DHCPINFORM);
}

int
bootrequest(struct request *req, void *vendor, ssize_t len)
{
	struct reply	 reply;
	struct lease	 fake;
	struct host	*h;
	u_int32_t	*magic = vendor, netmask;

	if ((h = shared_network_find_mac(req)) == NULL) {
		static char pview[48];

		snprintf(pview, sizeof pview, " magic %#x, len %zd",
		    ntohl(magic[0]), len);
		unsatisfied_log(req, "BOOTREQUEST", pview);
		return (0);
	}

	log_info("%s: BOOTREQUEST->BOOTREPLY: %s -> %s, magic %#x, len %zd",
	    req->shared->name, ether_ntoa(&req->bootp->chaddr.ether),
	    inet_ntoa(h->address), ntohl(magic[0]), len);

	memset(&fake, 0, sizeof fake);
	fake.host = h;
	fake.address = h->address;
	fake.group = h->group;
	fake.subnet = h->subnet;

	memset(&reply, 0, sizeof reply);
	reply.lease = &fake;

	/*
	 * RFC 1048 and 1534 say that we're allowed to fill the vendor space
	 * with DHCP options, but its size should stay fixed.
	 */
	if (dhcp_output(req, &reply) < 0)
		return (-1);
	reply.maxsize = BOOTP_VEND;

	netmask = htonl(plen2mask32(h->subnet->prefixlen));
	if (dhcp_add_tlv(&reply, DHCP_OPT_NETWORK_MASK, 4, &netmask) < 0)
		return (-1);
	if (dhcp_fill_options(req, &reply, h->group) < 0) {
		/* Space left for the End option? */
		if (reply.off > BOOTP_VEND - 1)
			return (-1);
	}
	if (dhcp_add_tlv(&reply, DHCP_OPT_END, 0, NULL) < 0)
		return (-1);

	/* Pad the rest of the option with zeroes. */
	if (reply.off < BOOTP_VEND)
		reply.off = BOOTP_VEND;

	++stats[STATS_BOOTREPLIES];
	return bootp_output(req, &reply);
}
