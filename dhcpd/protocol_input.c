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
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "dhcpd.h"

u_int64_t stats__unknown_received_options[256];

#define FAIL(fmt, ...)	do {			\
	log_warnx(fmt, __VA_ARGS__);		\
	++stats[STATS_DHCP_INVALID_OPTIONS];	\
	return (-1);				\
 } while (/* CONSTCOND */ 0)

#define ASSERT_NON_ZERO(str, val)	\
	if (val == 0)	FAIL("option %d: zero " str, type)
#define ASSERT_EQUAL(str, a, b)		\
	if ((a) != (b))	FAIL("option %d: " str " is %d, not %d", type, a, b)
#define ASSERT_MODULO(str, a, b)	\
	if ((a) % (b))	FAIL("option %d: " str " is %d, not mod %d", type, a, b)
#define ASSERT_GREATER_THAN(str, a, b)	\
	if ((a) <= (b))	FAIL("option %d: " str " is %d, not > %d", type, a, b)

static int
dhcp_option_validate(u_int8_t type, u_int8_t *len_data)
{
	const u_int8_t len = len_data[0];
	const u_int8_t *data = len_data + 1;

	switch (type) {
	case DHCP_OPT_ROUTERS:
	case DHCP_OPT_SERVERS_DNS:
	case DHCP_OPT_SERVERS_TFTP:
		ASSERT_MODULO("length", len, 4);
		break;

	case DHCP_OPT_RELAY_INFO:
		ASSERT_GREATER_THAN("length", len, 2);
		break;

	case DHCP_OPT_HOSTNAME:
	case DHCP_OPT_VENDOR_CLASSID:
		ASSERT_NON_ZERO("length", len);
		break;

	case DHCP_OPT_SERVER_ID:
	case DHCP_OPT_ADDR_REQUESTED:
	case DHCP_OPT_ADDR_LEASETIME:
		ASSERT_EQUAL("length", len, 4);
		break;

	case DHCP_OPT_CLIENT_ID:
		ASSERT_NON_ZERO("length", len);
		/* FALLTHROUGH */

	case DHCP_OPT_REQUEST_PARAMS:
	case DHCP_OPT_SYSTEM_ARCH:
	case DHCP_OPT_NET_DEV_IFACE:
		break;

	case DHCP_OPT_MESSAGE_TYPE:
		if (len != 1 || data[0] >= DHCP__MAXIMUM || data[0] == 0)
			FAIL("wrong DHCP message type %d len %d", data[0], len);
		break;

	default:
		++stats__unknown_received_options[type];
		break;
	}
	return (0);
}
#undef ASSERT_EQUAL
#undef ASSERT_MODULO
#undef ASSERT_NON_ZERO
#undef ASSERT_GREATER_THAN
#undef FAIL

int
dhcp_options_parse(u_int8_t *data, size_t len, u_int8_t **opts)
{
	u_int8_t *p = data;
	size_t needs_parsing = len;

	while (needs_parsing) {
		const u_int8_t type = p[0];
		const size_t length = needs_parsing > 1 ? p[1] + 2UL : 0;

		if (opts[type]) {
			++stats[STATS_DHCP_DUPLICATE_OPTIONS];
			log_warnx("option %d appeared twice", type);
			return (-1);
		}

		if (length > needs_parsing || length < 2) {
			/* It's actually very common, this padding after END. */
			if (type == DHCP_OPT_END)
				return (len);

			++stats[STATS_DHCP_BAD_LEN];
			log_warnx("option %d reaches past end of pkt", type);
			return (-1);
		}
		else if (length == 2) {
			switch (type) {
			case DHCP_OPT_END:
				/* This is an RFC-valid end of packet. */
				return (len);
			case DHCP_OPT_RAPID_COMMIT:
				/* ignore RFC 4039: DHCPv6 DISCOVER->ACK. */
				break;
			default:
				++stats[STATS_DHCP_BAD_LEN];
				log_warnx("option %d has zero length", type);
				return (-1);
			}
		}

		opts[type] = p + 1;
		if (dhcp_option_validate(type, opts[type]))
			return (-1);

		needs_parsing -= length;
		p += length;
	}
	return (len);
}

static int
dhcp_input(u_int8_t *data, size_t len, struct request *req)
{
	u_int8_t type;
	int result;

	result = dhcp_options_parse(data, len, req->dhcp_opts);

	if (req->dhcp_opts[DHCP_OPT_MESSAGE_TYPE] == NULL) {
		log_warnx("no message type option");
		return (-1);
	}
	if (req->dhcp_opts[DHCP_OPT_SERVER_ID]) {
		struct in_addr hers, mine;

		memcpy(&hers, req->dhcp_opts[DHCP_OPT_SERVER_ID] + 1, 4);
		mine = ipv4_addr(req->rcvd_on);
		if (mine.s_addr != hers.s_addr) {
			++stats[STATS_DHCP_NOT_FOR_US];
			log_warnx("packet not for me, but %s", inet_ntoa(hers));
			return (-1);
		}
	}

	switch ((type = req->dhcp_opts[DHCP_OPT_MESSAGE_TYPE][1])) {
	case DHCPDISCOVER:
		++stats[STATS_DISCOVERS];
		return dhcpdiscover(req);
	case DHCPREQUEST:
		++stats[STATS_REQUESTS];
		return dhcprequest(req);
	case DHCPDECLINE:
		++stats[STATS_DECLINES];
		return dhcpdecline(req);
	case DHCPRELEASE:
		++stats[STATS_RELEASES];
		return dhcprelease(req);
	case DHCPINFORM:
		++stats[STATS_INFORMS];
		return dhcpinform(req);
	default:
		++stats[STATS_DHCP_BAD_MESSAGE_TYPE];
		log_info("%s: message type %d not recognized", __func__, type);
		break;
	}

	return (result);
}

int
bootp_input(u_int8_t *data, size_t len, struct request *req)
{
	struct {
		struct bootp	bootp;
		union {
			struct {
				u_int32_t	magic;
				u_int8_t	options[308]; /* minimum */
			}		dhcp;
			u_int8_t	bootp_vend[BOOTP_VEND]; /* RFC 951 */
		}		tail;
	} *packet = (void *) data;

	if (len > MTU || len < sizeof packet->bootp + 4) {
		++stats[STATS_BOOTP_BAD_LEN];
		log_warnx("%s: rcvd packet of length %zu", __func__, len);
		return (-1);
	}

	req->bootp = &packet->bootp;

	if (packet->bootp.op != BOOTREQUEST) {
		++stats[STATS_BOOTP_NOT_BOOTREQUEST];
		log_info("NOT a BOOTREQUEST, but %u", packet->bootp.op);
		return (-1);
	}
	if (packet->bootp.htype != HTYPE_ETHERNET) {
		++stats[STATS_BOOTP_BAD_HTYPE];
		log_info("NOT a HTYPE_ETHERNET, but %u", packet->bootp.htype);
		return (-1);
	}
	if (packet->bootp.hlen != ETHER_ADDR_LEN) {
		++stats[STATS_BOOTP_BAD_HLEN];
		log_info("NOT a ETHER_ADDR_LEN, but %u", packet->bootp.hlen);
		return (-1);
	}

	/* Find the appropriate shared_network where did this originate. */
	if (packet->bootp.giaddr.s_addr != INADDR_ANY)
		req->shared = shared_network_from_relay(req);
	if (req->shared == NULL) {
		++stats[STATS_BOOTP_BAD_RELAY];
		log_warnx("%s: relay %s has no place here", __func__,
		    inet_ntoa(packet->bootp.giaddr));
		return (-1);
	}

	/* No DHCP magic?  It's a BOOTP packet. */
	if (packet->tail.dhcp.magic != ntohl(DHCP_OPTION_START_MAGIC)) {
		/*
		 * Strip away bits of the BOOTP header we parsed.
		 */
		if ((len -= sizeof(struct bootp)) < BOOTP_VEND) {
			++stats[STATS_BOOTP_BAD_LEN];
			log_info("%s: vendor options only %zu", __func__, len);
			return (-1);
		}

		++stats[STATS_BOOTREQUESTS];
		return bootrequest(req, &packet->tail.bootp_vend, len);
	}
	else {
		/*
		 * Strip away what have we parsed: the BOOTP header and the
		 * DHCP magic:	"offsetof(typeof(*packet), DHCP options)"
		 */
		len -= (char *) &packet->tail.dhcp.options - (char *) packet;

		return dhcp_input(packet->tail.dhcp.options, len, req);
	}
}
