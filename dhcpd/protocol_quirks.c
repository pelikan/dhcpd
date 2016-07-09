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
#include <time.h>

#include "dhcpd.h"

/*
 * Some DHCP options require special treatment that often depends on the input.
 * All these per-option quirks are static functions to this file and export via
 * "option_quirks" method table at the end of the file.
 */

static int
dhcp_fill_lease_time(struct reply *reply, struct request *req, u_int8_t type)
{
	static unsigned last_lease_time;
	unsigned current, remote, mult = 1, div = 1;

	if (reply->flags & REPLY_TO_DHCPINFORM)
		return (1);

	switch (type) {
	case DHCP_OPT_T1_RENEW_TIME:
		mult = 1;
		div = 2;
		break;
	case DHCP_OPT_T2_REBIND_TIME:
		mult = 2;
		div = 3;
		break;
	}

	switch (type) {
	case DHCP_OPT_ADDR_LEASETIME:
		/*
		 * We're using the fact that this option comes before the
		 * other two -> store the maximum in a static variable.
		 */
		current = reply->lease->expires.tv_sec - time(NULL);

		if (req->dhcp_opts[type]) {
			memcpy(&remote, req->dhcp_opts[type] + 1, 4);
			current = MIN(current, ntohl(remote));
		}

		current = htonl(current);
		if (dhcp_add_tlv(reply, type, 4, &current) < 0)
			return (-1);
		last_lease_time = ntohl(current);
		break;

	case DHCP_OPT_T1_RENEW_TIME:
	case DHCP_OPT_T2_REBIND_TIME:
		/* If the user specified these, fill them in directly. */
		if (reply->options[type]) {
			u_int8_t len = reply->options[type][0];
			u_int8_t *p = len ? reply->options[type] + 1 : NULL;

			if (dhcp_add_tlv(reply, type, len, p) < 0)
				return (-1);
		}
		else {
			current = htonl(mult * last_lease_time / div);

			if (dhcp_add_tlv(reply, type, 4, &current) < 0)
				return (-1);
		}
		break;
	}
	return (1);
}

static int
dhcp_fill_servers_tftp(struct reply *reply, struct request *req, u_int8_t type)
{
	u_int8_t len, *p;
	int i;

	/* Fill them in in the regular path, if configured. */
	if (type != DHCP_OPT_SERVERS_TFTP || reply->options[type])
		return (0);

	/* If this has been requested, fake it with "next-address" siaddr. */
	if ((p = req->dhcp_opts[DHCP_OPT_REQUEST_PARAMS]) == NULL)
		return (1);

	/* Go over the Parameter Request List in the request packet. */
	len = p[0];
	for (i = 0; i < len; ++i)
		if (p[1 + i] == DHCP_OPT_SERVERS_TFTP)
			break;

	/* Not found or nothing to fake it with? */
	if (i == len || reply->next_server == NULL)
		return (1);

	return (dhcp_add_tlv(reply, type, 4, reply->next_server) < 0) ? -1 : 1;
}

int(* const option_quirks[256])(struct reply *, struct request *, u_int8_t) = {
 /* 0*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
 /*10*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
 /*20*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
 /*30*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
 /*40*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
 /*50*/	NULL,
 /*51*/	dhcp_fill_lease_time,				/* Lease Time */
 /*52*/	NULL, NULL, NULL, NULL, NULL, NULL,
 /*58*/	dhcp_fill_lease_time, dhcp_fill_lease_time,	/* T1 and T2 */
 /*60*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
 /*70*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
 /*80*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
 /*90*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/*100*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/*110*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/*120*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/*130*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/*140*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/*150*/	dhcp_fill_servers_tftp,			/* Multiple TFTP servers */
/*151*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
/*160*/	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};

