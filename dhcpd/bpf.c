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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "dhcpd.h"

/*
 * Unprivileged functions emulating the network stack for BPF.
 */

static u_int32_t
wrapsum(u_int32_t sum)
{
	return htons(~sum & 0xFFFF);
}

static u_int32_t
checksum(void *p, size_t len, u_int32_t sum)
{
	union {
		u_int16_t	*u16;
		u_int8_t	*u8;
	} data = { p };
	size_t i;

	/* The original code did two bytes at a time. */
	for (i = 0; i < (len / 2); ++i)
		if ((sum += ntohs(data.u16[i])) > 0xFFFF)
			sum -= 0xFFFF;

	/* The last odd byte (high, we're big-endian)... don't forget. */
	if ((len & 0x1) && (sum += (data.u8[len - 1] << 8)) > 0xFFFF)
		sum -= 0xFFFF;

	return (sum);
}

int
ether_input(void *data, size_t len, struct request *req)
{
	req->l2 = data;

	if (req->l2->ether_type != htons(ETHERTYPE_IP))
		fatalx("non-IPv4 packet happened: BPF doesn't work.");

	if (len > MTU || len <= sizeof *req->l2) {
		log_warnx("%s: rcvd packet of length %zu", __func__, len);
		return (-1);
	}

	return (sizeof *req->l2);
}

int
ipv4_input(void *data, size_t len, struct request *req)
{
	u_int8_t	*buf = data;
	int		 hdrlen, ip_len;

	req->l3 = data;
	hdrlen = (buf[0] & 0x0F) << 2;

	if ((buf[0] & 0xF0) != 0x40) {
		log_warnx("%s: wrong IP version byte %#x", __func__, buf[0]);
		return (-1);
	}

	ip_len = ntohs(req->l3->ip_len);
	if (len > MTU || (int) len != ip_len) {
		++stats[STATS_IP_BAD_LEN];
		log_warnx("%s: rcvd packet of length %zu, IPv4 says %u",
		    __func__, len, ip_len);
		return (-1);
	}

	if (req->l3->ip_p != IPPROTO_UDP)
		fatalx("wrong IP protocol: BPF doesn't work.");

	if (wrapsum(checksum(data, hdrlen, 0)) != 0) {
		log_warnx("%s: bad checksum", __func__);
		return (-1);
	}

	if ((req->rcvd_on = bpf_address(req)) == NULL)
		return (-1);

	return (hdrlen);
}


int
udp_input(void *data, size_t len, struct request *req)
{
	u_int32_t sum, origsum;
	size_t uh_ulen;

	req->l4 = data;

	uh_ulen = ntohs(req->l4->uh_ulen);
	if (len > MTU || len != uh_ulen) {
		++stats[STATS_UDP_BAD_LEN];
		log_warnx("%s: rcvd packet of length %zu, UDP says %u",
		    __func__, len, uh_ulen);
		return (-1);
	}

	if (req->l4->uh_dport != htons(BOOTP_SERVER_PORT))
		fatalx("wrong UDP dport: BPF doesn't work.");

	if ((origsum = req->l4->uh_sum) != 0) {
		req->l4->uh_sum = 0;

		sum = uh_ulen + IPPROTO_UDP;
		sum = checksum(&req->l3->ip_src,
		    2 * sizeof(struct in_addr), sum);
		sum = checksum((char *) data + sizeof *req->l4,
		    len - sizeof *req->l4, sum);
		sum = checksum(data, sizeof *req->l4, sum);
		if (wrapsum(sum) != origsum) {
			log_warnx("%s: bad checksum", __func__);
			return (-1);
		}
	}

	return sizeof *req->l4;
}

int
udp_output(struct reply *reply, struct request *req)
{
	unsigned short len;

	(void) req;
	len = sizeof reply->pkt.l4 + sizeof reply->pkt.bootp + reply->off;

	reply->pkt.l4.uh_sport = htons(BOOTP_SERVER_PORT);
	reply->pkt.l4.uh_dport = htons(BOOTP_CLIENT_PORT);
	reply->pkt.l4.uh_ulen = htons(len);

	/* UDP checksum needs IPv4 fields...  It's not just IPv6 that's bad.  */

	return sizeof reply->pkt.l4;
}

int
ipv4_output(struct reply *reply, struct request *req)
{
	unsigned short len;
	u_int32_t sum;

	if (reply->off <= 0)
		fatalx("bad reply offset");

	len = sizeof reply->pkt.bootp + reply->off;

	reply->pkt.l3.ip_v = 4;
	reply->pkt.l3.ip_hl = 5;
	reply->pkt.l3.ip_ttl = 16;
	reply->pkt.l3.ip_len = htons(len +
	    sizeof reply->pkt.l3 + sizeof reply->pkt.l4);
	reply->pkt.l3.ip_tos = IPTOS_LOWDELAY;
	reply->pkt.l3.ip_p = IPPROTO_UDP;

	reply->pkt.l3.ip_src = ipv4_addr(req->rcvd_on);
	reply->pkt.l3.ip_dst = destination(reply, req, &reply->pkt.l4.uh_dport);

	/* Fill in IPv4 checksum. */
	sum = checksum(&reply->pkt.l3, sizeof reply->pkt.l3, 0);
	reply->pkt.l3.ip_sum = wrapsum(sum);

	/* Fill in UDP checksum, now that we have the IPv4 header. */
	sum = ntohs(reply->pkt.l4.uh_ulen) + IPPROTO_UDP;
	sum = checksum(&reply->pkt.l3.ip_src, 2 * sizeof(struct in_addr), sum);
	sum = checksum(&reply->pkt.bootp, len, sum);
	sum = checksum(&reply->pkt.l4, sizeof reply->pkt.l4, sum);
	reply->pkt.l4.uh_sum = wrapsum(sum);

	return 20;
}

int
ether_output(struct reply *r, struct request *req)
{
	const size_t len = sizeof req->l2->ether_dhost;

	if (r->pkt.l3.ip_dst.s_addr == INADDR_BROADCAST)
		memset(&r->pkt.l2.ether_dhost, 0xFF, len);
	else
		memcpy(&r->pkt.l2.ether_dhost, r->pkt.bootp.chaddr.buf, len);

	/*
	 * OpenBSD route(4) RTM_IFANNOUNCE messages don't tell
	 * link layer addresses about interfaces that came later
	 * in the process.  Therefore just copy where it came from.
	 */
	memcpy(&r->pkt.l2.ether_shost, req->l2->ether_dhost, len);
	r->pkt.l2.ether_type = htons(ETHERTYPE_IP);

	return sizeof r->pkt.l2;
}
