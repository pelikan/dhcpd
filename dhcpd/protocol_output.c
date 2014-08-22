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

#include <string.h>

#include "dhcpd.h"

extern int(* const option_quirks[256])(struct reply *, struct request *, u_int8_t);
u_int64_t stats__unknown_requested_options[256];

int
dhcp_fill_options(struct request *req, struct reply *reply, struct group *g)
{
	struct lease	*l = reply->lease;
	struct group	*ga[] = { g, l->subnet->group, req->shared->group };
	u_int8_t	 len, *p;
	size_t		 i;

	if (req->shared != l->subnet->shared)
		fatalx("request's shared network doesn't match subnet's!");

	/* The default group is searched only as a last resort. */
	for (i = 0; i < sizeof ga / sizeof *ga; ++i)
		if (ga[i] != &default_group)
			group_copyout_chain(reply, ga[i]);

	group_copyout_chain(reply, &default_group);

	/* DHCPACKs extend the lease time, but DHCPINFORM can't touch leases. */
	if ((reply->flags & (REPLY_EXTEND_LEASE | REPLY_TO_DHCPINFORM)) ==
	    REPLY_EXTEND_LEASE)
		lease_extend(reply);

	/* Fill the packet with whatever these groups gave us. */
	for (i = 0; i < 256; ++i) {
		if (option_quirks[i])
			switch (option_quirks[i](reply, req, i)) {
			case (-1):
				return (-1);
			case (0):
				break;
			default:
				continue;
			}

		if (reply->options[i] == NULL)
			continue;

		len = reply->options[i][0];
		p = len ? reply->options[i] + 1 : NULL;

		if (dhcp_add_tlv(reply, i, len, p) < 0)
			return (-1);
	}

	/* RFC 3046: Relay Agent Information SHOULD be the last option. */
	if ((p = req->dhcp_opts[DHCP_OPT_RELAY_INFO])) {
		len = p[0];
		++p;

		if (dhcp_add_tlv(reply, DHCP_OPT_RELAY_INFO, len, p) < 0)
			return (-1);
	}

	/* Count all DHCP options that clients wanted and we didn't have. */
	if ((p = req->dhcp_opts[DHCP_OPT_REQUEST_PARAMS])) {
		len = p[0];
		++p;

		for (i = 0; i < len; ++i) {
			/* These option are always filled in. */
			switch (p[i]) {
			case DHCP_OPT_NETWORK_MASK:
			case DHCP_OPT_ADDR_LEASETIME:
			case DHCP_OPT_SERVER_ID:
			case DHCP_OPT_T1_RENEW_TIME:
			case DHCP_OPT_T2_REBIND_TIME:
				continue;
			}
			if (reply->options[p[i]] == NULL)
				++stats__unknown_requested_options[p[i]];
		}
	}
	return (0);
}

/* Currently we don't do the magic with @reply->bootp.{sname,filename} reuse. */
int
dhcp_add_tlv(struct reply *reply, u_int8_t type, u_int8_t len, void *p)
{
	unsigned off = reply->off;
	unsigned noff = off + (len ? len + 2 : 1);

	if (reply->maxsize < BOOTP_VEND)
		fatalx("reply maximum message size not filled in/too small");

	if (noff >= (unsigned) reply->maxsize) {
		++stats[STATS_DHCP_NO_SPACE];
		log_warnx("%s: option %d too big for %d: %d, limit %d",
		    __func__, type, off, len, reply->maxsize);
		return (-1);
	}

	reply->pkt.option_space[off] = type;
	if (len) {
		reply->pkt.option_space[off + 1] = len;
		memcpy(reply->pkt.option_space + off + 2, p, len);
		reply->off = noff;
	}
	else
		++reply->off;

	return (0);
}

int
bootp_output(struct request *req, struct reply *reply)
{
	/* RFC 1542, section 3.3 */
	reply->pkt.bootp.ciaddr = req->bootp->ciaddr;
	reply->pkt.bootp.yiaddr = reply->lease->address;
	/* RFC 1542, section 4.1.2, "to identify logical interface" */
	reply->pkt.bootp.giaddr = req->bootp->giaddr;

	if (reply->next_server)
		memcpy(&reply->pkt.bootp.siaddr, reply->next_server,
		    sizeof(struct in_addr));

	if (reply->sname)
		strlcpy(reply->pkt.bootp.sname, reply->sname, BOOTP_SNAME);

	if (reply->filename)
		strlcpy(reply->pkt.bootp.file, reply->filename, BOOTP_FILE);

	reply->pkt.bootp.op = BOOTREPLY;
	reply->pkt.bootp.htype = req->bootp->htype;
	reply->pkt.bootp.hlen = req->bootp->hlen;
	reply->pkt.bootp.xid = req->bootp->xid;
	reply->pkt.bootp.chaddr = req->bootp->chaddr;

	/* RFC 1542, section 5.4, paragraph 3. */
	reply->pkt.bootp.flags = req->bootp->flags;

	return sendit(req, reply);
}

int
dhcp_output(struct request *req, struct reply *reply)
{
	const u_int32_t magic = htonl(DHCP_OPTION_START_MAGIC);
	u_int16_t maxsize = 0;
	u_int8_t *p;

	if (reply->off)
		fatalx("dhcp_output called in the wrong place");

	memcpy(reply->pkt.option_space, &magic, sizeof magic);
	reply->off = 4;
	reply->maxsize = sizeof reply->pkt.option_space;

	/*
	 * RFC 2132, section 9.10:  The minimum legal value is 576 octets.
	 * RFC 3442, page 6: client SHOULD set the value to at least MTU [...]
	 * Microsoft has got it wrong:
	 * http://technet.microsoft.com/en-us/library/cc977417.aspx
	 */
	if ((p = req->dhcp_opts[DHCP_OPT_MAX_MSG_SIZE])) {
		if (p[0] != 2)
			goto illegal;
		if ((maxsize = (p[1] << 8U) | p[2]) < 576)
			goto illegal;
		reply->maxsize = maxsize -
		    ((char *) &reply->pkt.option_space - (char *) &reply->pkt);

		if (reply->maxsize < BOOTP_VEND)
			reply->maxsize = BOOTP_VEND;
		if (reply->maxsize > (int) sizeof reply->pkt.option_space)
			reply->maxsize = sizeof reply->pkt.option_space;
	}
	return (0);

 illegal:
	log_info("%s: ignoring Maximum DHCP Message Size %u, len %u: using %d",
	    __func__, maxsize, p[0], reply->maxsize);
	/* Let's ignore them, because Sony Bravia TVs send illegal values. */
	return (1);
}
