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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <assert.h>
#include <err.h>
#include <imsg.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vis.h>

#include "dhcpd.h"
#include "parser.h"

#define	DHCPD_SAID		"dhcpd said: %s"
#define	DHCPD_WRONG_IMSG	"wrong answer: imsg type %d len %d"

struct sockaddr_un sun = { sizeof PATH_CTLSOCK, AF_UNIX, PATH_CTLSOCK };
struct imsgbuf ibuf;
int quit = 0;
char error_buffer[ERR_BUF_SIZE * 4];	/* enough for strvis(3) */

static int	do_shell(void);

static int
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s\n", __progname);
	return (EXIT_FAILURE);
}

#define MINUTE	(60)
#define HOUR	(MINUTE * 60)
#define DAY	(HOUR * 24)
#define WEEK	(DAY * 7)
static char *
print_time(unsigned total)
{
	unsigned x;
	static char ret[32];
	size_t pos = 0;

	if ((x = total / WEEK) != 0) {
		pos += snprintf(ret + pos, sizeof ret - pos, "%uw", x);
		total -= x * WEEK;
	}
	if ((x = total / DAY) != 0) {
		pos += snprintf(ret + pos, sizeof ret - pos, "%ud", x);
		total -= x * DAY;
	}
	if ((x = total / HOUR) != 0) {
		pos += snprintf(ret + pos, sizeof ret - pos, "%uh", x);
		total -= x * HOUR;
	}
	if ((x = total / MINUTE) != 0) {
		pos += snprintf(ret + pos, sizeof ret - pos, "%um", x);
		total -= x * MINUTE;
	}
	if (total != 0) {
		pos += snprintf(ret + pos, sizeof ret - pos, "%us", total);
	}
	return (ret);
}
#undef MINUTE
#undef HOUR
#undef DAY
#undef WEEK

static void
tell_server_to_quit(void)
{
	if (imsg_compose(&ibuf, IMSG_DONE, 0, 0, -1, NULL, 0) == -1)
		fprintf(stderr, "imsg_compose failed\n");

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");
}

static void
get_boring_response(void)
{
	struct imsg imsg;
	ssize_t n;

	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
}

static void
do_interface(struct parse_result *res, int op)
{
	struct ctl_interface i;

	memset(&i, 0, sizeof i);
	strlcpy(i.name, res->interface, sizeof i.name);
	strlcpy(i.shared, res->string, sizeof i.shared);

	imsg_compose(&ibuf, op, 0, 0, -1, &i, sizeof i);
	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
}

static void
do_interface_list(void)
{
	struct ctl_interface	*ctlif;
	struct imsg	 	 imsg;
	ssize_t			 n;

	imsg_compose(&ibuf, IMSG_LISTEN_INTERFACE_LIST, 0, 0, -1, NULL, 0);
	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");
 again:
	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			quit = 1;
			break;
		case IMSG_LISTEN_INTERFACE_LIST:
			ctlif = imsg.data;
			assert((count % sizeof *ctlif) == 0);
			count /= sizeof *ctlif;

			if (count == 0)
				puts("no interfaces running/waiting");

			for (size_t i = 0; i < count; ++i)
				printf("- %u: %s, shared network: %s\n",
				    ctlif[i].index, ctlif[i].name,
				    ctlif[i].shared);
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
	if (quit == 0)
		goto again;
}

static void
do_address(struct parse_result *res, int op)
{
	struct ctl_address	a;

	memset(&a, 0, sizeof a);
	a.ipv4 = res->ipv4_1;
	strlcpy(a.shared, res->string, sizeof a.shared);

	imsg_compose(&ibuf, op, 0, 0, -1, &a, sizeof a);
	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
}

static void
do_address_list(void)
{
	struct ctl_address	*ctla;
	struct imsg	 	 imsg;
	ssize_t			 n;

	imsg_compose(&ibuf, IMSG_LISTEN_ADDRESS_LIST, 0, 0, -1, NULL, 0);
	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");
 again:
	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			quit = 1;
			break;
		case IMSG_LISTEN_ADDRESS_LIST:
			ctla = imsg.data;
			assert((count % sizeof *ctla) == 0);
			count /= sizeof *ctla;

			if (count == 0)
				puts("no UDP sockets running/waiting");

			for (size_t i = 0; i < count; ++i)
				printf("- %s, default shared network: %s\n",
				    inet_ntoa(ctla[i].ipv4), ctla[i].shared);
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
	if (quit == 0)
		goto again;
}

static void
do_relay(struct parse_result *res, int op)
{
	struct ctl_relay r;

	memset(&r, 0, sizeof r);
	strlcpy(r.shared, res->string, sizeof r.shared);
	r.relay = res->ipv4_1;
	r.dst = res->ipv4_2;

	imsg_compose(&ibuf, op, 0, 0, -1, &r, sizeof r);
	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
}

static void
do_relay_list(struct in_addr where)
{
	struct ctl_relay  r, *buf;
	struct imsg	  imsg;
	ssize_t		  n;

	imsg_compose(&ibuf, IMSG_RELAY_LIST, 0, 0, -1, &where, sizeof where);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");
 again:
	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			quit = 1;
			break;
		case IMSG_RELAY_LIST:
			buf = imsg.data;
			assert((count % sizeof r) == 0);
			count /= sizeof r;

			for (size_t i = 0; i < count; ++i) {
				char x[20], y[20];
				strlcpy(x, (buf[i].relay.s_addr == INADDR_ANY) ?
				    "any" : inet_ntoa(buf[i].relay), sizeof x);
				strlcpy(y, inet_ntoa(buf[i].dst), sizeof y);
				printf("%s\t%s\t%s\n", x, y, buf[i].shared);
			}
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
	if (quit == 0)
		goto again;
}

static void
do_shared_network(struct parse_result *res, int op)
{
	struct ctl_shared s;

	memset(&s, 0, sizeof s);
	strlcpy(s.name, res->string, sizeof s.name);
	strlcpy(s.group, res->group, sizeof s.group);

	imsg_compose(&ibuf, op, 0, 0, -1, &s, sizeof s);
	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
}

static void
do_shared_network_list(void)
{
	struct ctl_shared s, *buf;
	struct imsg	  imsg;
	ssize_t		  n;

	imsg_compose(&ibuf, IMSG_SHARED_NETWORK_LIST, 0, 0, -1, NULL, 0);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");
 again:
	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			quit = 1;
			break;
		case IMSG_SHARED_NETWORK_LIST:
			buf = imsg.data;
			assert((count % sizeof s) == 0);
			count /= sizeof s;

			for (size_t i = 0; i < count; ++i)
				printf("- %s\n", buf[i].name);
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
	if (quit == 0)
		goto again;
}

static void
do_subnet(struct parse_result *res, int op)
{
	struct ctl_subnet s;

	memset(&s, 0, sizeof s);
	strlcpy(s.shared, res->string, sizeof s.shared);
	strlcpy(s.group, res->group, sizeof s.group);
	s.network = res->network;
	s.prefixlen = res->prefixlen;

	imsg_compose(&ibuf, op, 0, 0, -1, &s, sizeof s);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
}

static void
do_subnet_set(struct parse_result *res, int op)
{
	struct ctl_subnet_settings ss;

	memset(&ss, 0, sizeof ss);
	ss.flags |= SUBNET_WANT_RANGE;
	ss.range_lo = res->ipv4_1;
	ss.range_hi = res->ipv4_2;
	strlcpy(ss.shared, res->string, sizeof ss.shared);
	ss.network = res->network;
	ss.prefixlen = res->prefixlen;

	imsg_compose(&ibuf, op, 0, 0, -1, &ss, sizeof ss);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
}

static void
do_subnet_list(char *shared)
{
	struct ctl_subnet s, *buf;
	struct imsg	  imsg;
	ssize_t		  n;

	memset(&s, 0, sizeof s);
	strlcpy(s.shared, shared, sizeof s.shared);

	imsg_compose(&ibuf, IMSG_SUBNET_LIST, 0, 0, -1, &s, sizeof s);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");
 again:
	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			quit = 1;
			break;
		case IMSG_SUBNET_LIST:
			buf = imsg.data;
			assert((count % sizeof s) == 0);
			count /= sizeof s;

			for (size_t i = 0; i < count; ++i)
				printf("- %s %s/%u\n", buf[i].shared,
				    inet_ntoa(buf[i].network),
				    buf[i].prefixlen);
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
	if (quit == 0)
		goto again;
}

static void
do_subnet_show(struct parse_result *res)
{
	struct ctl_subnet_settings *sbuf;
	struct ctl_host	 *hbuf;
	struct ctl_subnet s;
	struct imsg	  imsg;
	ssize_t		  n;

	memset(&s, 0, sizeof s);
	s.network = res->network;
	s.prefixlen = res->prefixlen;
	strlcpy(s.shared, res->string, sizeof s.shared);

	imsg_compose(&ibuf, IMSG_SUBNET_SHOW, 0, 0, -1, &s, sizeof s);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");
 again:
	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			quit = 1;
			break;
		case IMSG_SUBNET_SET:
			sbuf = imsg.data;
			assert((count % sizeof *sbuf) == 0);
			count /= sizeof *sbuf;

			for (size_t i = 0; i < count; ++i) {
				char x[20], y[20];

				strlcpy(x,inet_ntoa(sbuf[i].range_lo),sizeof x);
				strlcpy(y,inet_ntoa(sbuf[i].range_hi),sizeof y);
				printf("- range %s %s\n", x, y);
			}
			break;
		case IMSG_SUBNET_SHOW:
			hbuf = imsg.data;
			assert((count % sizeof *hbuf) == 0);
			count /= sizeof *hbuf;

			for (size_t i = 0; i < count; ++i)
				printf("%s\t%s\n", inet_ntoa(hbuf[i].ip),
				    ether_ntoa(&hbuf[i].mac));
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
	if (quit == 0)
		goto again;
}

static void
do_host(struct parse_result *res, int op)
{
	struct ctl_host	 h;

	memset(&h, 0, sizeof h);
	strlcpy(h.shared, res->string, sizeof h.shared);
	strlcpy(h.group, res->group, sizeof h.group);
	memcpy(&h.mac, &res->mac, ETHER_ADDR_LEN);
	h.ip = res->ipv4_1;

	imsg_compose(&ibuf, op, 0, 0, -1, &h, sizeof h);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
}

static void
do_lease_kill(struct parse_result *res)
{
	struct ctl_lease l;

	memset(&l, 0, sizeof l);
	strlcpy(l.shared, res->string, sizeof l.shared);
	memcpy(&l.mac, &res->mac, ETHER_ADDR_LEN);
	l.ip = res->ipv4_1;

	imsg_compose(&ibuf, IMSG_LEASE_RELEASE, 0, 0, -1, &l, sizeof l);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
}

static void
do_group_create(struct parse_result *res)
{
	struct ctl_group g;

	memset(&g, 0, sizeof g);
	strlcpy(g.name, res->group, sizeof g.name);

	imsg_compose(&ibuf, IMSG_GROUP_CREATE, 0, 0, -1, &g, sizeof g);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
}

static void
do_group_list(void)
{
	struct ctl_group  g, *buf;
	struct imsg	  imsg;
	ssize_t		  n;

	imsg_compose(&ibuf, IMSG_GROUP_LIST, 0, 0, -1, NULL, 0);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");
 again:
	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			quit = 1;
			break;
		case IMSG_GROUP_LIST:
			buf = imsg.data;
			assert((count % sizeof g) == 0);
			count /= sizeof g;

			for (size_t i = 0; i < count; ++i)
				printf("- %s\n", buf[i].name);
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
	if (quit == 0)
		goto again;
}

static char *
lease_state(int s)
{
	switch (s) {
	case OFFERED:	return "offered";
	case ACKED:	return "acked";
	case DECLINED:	return "<declined>";
	default:	return "<unknown>";
	}
}

static void
print_lease(struct ctl_lease *l, struct timeval *now)
{
	char buf[256], *exptm;

	exptm = timercmp(&l->expires, now, <=) ? "expired" :
	    print_time(l->expires.tv_sec - now->tv_sec);

	printf("- %s %s %s %s %s", ether_ntoa(&l->mac), inet_ntoa(l->ip),
	    l->shared, lease_state(l->state), exptm);

	if (l->last_hostname[0]) {
		l->last_hostname[sizeof l->last_hostname -1] = '\0';
		strnvis(buf, l->last_hostname, sizeof buf, VIS_SAFE);
		printf(" %s", buf);
	}
	if (l->last_vendor_classid[0]) {
		l->last_vendor_classid[sizeof l->last_vendor_classid -1] = '\0';
		strnvis(buf, l->last_vendor_classid, sizeof buf, VIS_SAFE);
		printf(" %s", buf);
	}
	puts("");
}

static void
do_leases(void)
{
	struct ctl_lease l, *buf;
	struct imsg	 imsg;
	ssize_t		 n;
	struct timeval	 now;

	imsg_compose(&ibuf, IMSG_LEASES_DUMP, 0, 0, -1, NULL, 0);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");
 again:
	gettimeofday(&now, NULL);
	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			quit = 1;
			break;
		case IMSG_LEASES_DUMP:
			buf = imsg.data;
			assert((count % sizeof l) == 0);
			count /= sizeof l;

			for (size_t i = 0; i < count; ++i)
				print_lease(buf + i, &now);
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
	if (quit == 0)
		goto again;
}

/*
 * XXX This is currently just a scaffolding to support multiple options from
 * XXX a proper file later.  You can now set options one by one like this:
 * XXX sudo ./dhcpctl group tlv-set potazmo bytes 6 4 `printf "\xC0\xA8\x90\x1E"`
 */
static void
do_group_set(struct parse_result *res)
{
	struct ctl_group_settings *gs;
	size_t len;

	if (res->opt_type) {
		if (strcmp(res->syntax, "bytes") == 0) {
			/* XXX Pray there isn't any overflow. */
		}
		else if (strcmp(res->syntax, "IP") == 0) {
			struct in_addr a;

			if (inet_aton((char *) res->opt_value, &a) == 0)
				errx(1, "invalid IP address");
			memcpy(res->opt_value, &a, 4);
			res->opt_length = 4;
		}
		else if (strcmp(res->syntax, "IP-list") == 0) {
			parse_ip_list();
			if (res->ipv4_list_cnt > sizeof res->opt_value / 4)
				errx(1, "too many IP addresses");
			res->opt_length = 4 * res->ipv4_list_cnt;
			memcpy(res->opt_value, res->ipv4_list, res->opt_length);
		}
		else
			errx(1, "how to parse the value?  bytes|IP");
	}

	len = offsetof(struct ctl_group_settings, options) + res->opt_length +2;
	if ((gs = calloc(1, len)) == NULL)
		errx(1, "out of memory: %zu bytes", len);;

	gs->flags = res->flags;
	if (gs->flags & GROUP_WANT_FILENAME)
		strlcpy(gs->filename, res->filename, sizeof gs->filename);
	if (gs->flags & GROUP_WANT_SNAME)
		strlcpy(gs->sname, res->sname, sizeof gs->sname);
	if (gs->flags & GROUP_WANT_NEXT_SERVER)
		gs->next_server = res->ipv4_1;

	strlcpy(gs->parent, res->string, sizeof gs->parent);
	strlcpy(gs->name, res->group, sizeof gs->name);
	gs->options[0] = res->opt_type;
	gs->options[1] = res->opt_length;
	memcpy(gs->options + 2, res->opt_value, res->opt_length);

	imsg_compose(&ibuf, IMSG_GROUP_SET, 0, 0, -1, gs, len);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
	free(gs);
}

/*
 * XXX This is currently just a scaffolding to support multiple options from
 * XXX a proper file later.  You can now unset options one by one like this:
 * XXX sudo ./dhcpctl group tlv-unset potazmo 1 `printf "\x06"`
 */
static void
do_group_unset(struct parse_result *res)
{
	struct ctl_group_settings *gs;
	size_t len;
	int i;

	printf("group %s: unsetting ", res->group);
	for (i = 0; i < res->opt_length; ++i)
		printf("%x ", res->opt_value[i]);
	puts("");

	len = offsetof(struct ctl_group_settings, options) + res->opt_length;
	if ((gs = calloc(1, len)) == NULL)
		errx(1, "out of memory: %zu bytes", len);;

	strlcpy(gs->name, res->group, sizeof gs->name);
	memcpy(gs->options, res->opt_value, res->opt_length);

	imsg_compose(&ibuf, IMSG_GROUP_UNSET, 0, 0, -1, gs, len);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

	get_boring_response();
	free(gs);
}

static void
do_extra_stats(u_int64_t *s)
{
	time_t now, uptime;

	time(&now);
	uptime = now - s[STATS_DAEMON_STARTED];

	printf("options.nospace=%" PRIu64 "\n", s[STATS_DHCP_NO_SPACE]);
	printf("options.invalid=%" PRIu64 "\n", s[STATS_DHCP_INVALID_OPTIONS]);
	printf("options.duplicate=%" PRIu64 "\n",
	    s[STATS_DHCP_DUPLICATE_OPTIONS]);

	printf("uptime=%" PRIu64 "\n", uptime);
	printf("uptime.human=%s\n", print_time(uptime));
	printf("leases.current=%" PRIu64 "\n", s[STATS_LEASES_PRESENT]);

	printf("packets.received.bootrequests=%" PRIu64 "\n",
	    s[STATS_BOOTREQUESTS]);
	printf("packets.sent.bootreplies=%" PRIu64 "\n", s[STATS_BOOTREPLIES]);
	printf("packets.received.discovers=%" PRIu64 "\n", s[STATS_DISCOVERS]);
	printf("packets.sent.offers=%" PRIu64 "\n", s[STATS_OFFERS]);
	printf("packets.received.requests=%" PRIu64 "\n", s[STATS_REQUESTS]);
	printf("packets.received.requests.initreboot=%" PRIu64 "\n",
	    s[STATS_REQUESTS_INIT_REBOOT]);
	printf("packets.received.requests.renewing=%" PRIu64 "\n",
	    s[STATS_REQUESTS_RENEWING]);
	printf("packets.received.requests.rebinding=%" PRIu64 "\n",
	    s[STATS_REQUESTS_REBINDING]);
	printf("packets.received.requests.selecting=%" PRIu64 "\n",
	    s[STATS_REQUESTS_SELECTING]);
	printf("packets.received.declines=%" PRIu64 "\n", s[STATS_DECLINES]);
	printf("packets.sent.acks=%" PRIu64 "\n", s[STATS_ACKS]);
	printf("packets.sent.naks=%" PRIu64 "\n", s[STATS_NAKS]);
	printf("packets.received.releases=%" PRIu64 "\n", s[STATS_RELEASES]);
	printf("packets.received.informs=%" PRIu64 "\n", s[STATS_INFORMS]);

	printf("packets.badlength.ip=%" PRIu64 "\n", s[STATS_IP_BAD_LEN]);
	printf("packets.badlength.udp=%" PRIu64 "\n", s[STATS_UDP_BAD_LEN]);
	printf("packets.badlength.bootp=%" PRIu64 "\n", s[STATS_BOOTP_BAD_LEN]);
	printf("packets.badlength.dhcp=%" PRIu64 "\n", s[STATS_DHCP_BAD_LEN]);

	printf("packets.bootp.nrequest=%" PRIu64 "\n",
	    s[STATS_BOOTP_NOT_BOOTREQUEST]);
	printf("packets.bootp.badhtype=%" PRIu64 "\n",
	    s[STATS_BOOTP_BAD_HTYPE]);
	printf("packets.bootp.badhlen=%" PRIu64 "\n", s[STATS_BOOTP_BAD_HLEN]);
	printf("packets.bootp.badrelay=%" PRIu64 "\n",
	    s[STATS_BOOTP_BAD_RELAY]);

	printf("packets.dhcp.badmsgtype=%" PRIu64 "\n",
	    s[STATS_DHCP_BAD_MESSAGE_TYPE]);
	printf("packets.dhcp.notours=%" PRIu64 "\n", s[STATS_DHCP_NOT_FOR_US]);
	printf("packets.dhcp.notfound=%" PRIu64 "\n", s[STATS_DHCP_NOT_FOUND]);
}

static void
do_stats(void)
{
	u_int64_t	 *buf;
	struct imsg	 imsg;
	ssize_t		 n;
	const char	*desc;

	imsg_compose(&ibuf, IMSG_STATS, 0, 0, -1, NULL, 0);

	if (imsg_flush(&ibuf))
		err(1, "imsg_flush");

 again:
	if ((n = imsg_read(&ibuf)) == -1)
		err(1, "imsg_read");

	while ((n = imsg_get(&ibuf, &imsg)) > 0) {
		size_t count = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_ERROR:
			strvisx(error_buffer, imsg.data, count, VIS_SAFE);
			warnx(DHCPD_SAID, error_buffer);
			/* FALLTHROUGH */
		case IMSG_DONE:
			quit = 1;
			break;
		case IMSG_STATS:
			buf = imsg.data;
			assert((count % sizeof *buf) == 0);
			count /= sizeof *buf;
			assert(count == 512 + STATS__MAXIMUM);

			for (size_t i = 0; i < 512; ++i) {
				if (buf[i] == 0)
					continue;

				desc = (i >= 256) ? "received" : "requested";
				printf("options.unknown.%s.%zu=%" PRIu64 "\n",
				    desc, i % 256, buf[i]);
			}
			do_extra_stats(buf + 512);
			break;
		default:
			errx(1, DHCPD_WRONG_IMSG, imsg.hdr.type, imsg.hdr.len);
		}
		imsg_free(&imsg);
	}

	if (n == -1)
		err(1, "imsg_get");
	if (quit == 0)
		goto again;
}

static int
action_switch(struct parse_result *res, int in_shell)
{
	quit = 0;
	switch (res->action) {
	case SHELL:
		if (in_shell)
			return (EXIT_SUCCESS);
		do_shell();
		break;
	case INTERFACE_ADD:
		do_interface(res, IMSG_LISTEN_INTERFACE_ADD);
		break;
	case INTERFACE_DELETE:
		do_interface(res, IMSG_LISTEN_INTERFACE_DELETE);
		break;
	case INTERFACE_LIST:
		do_interface_list();
		break;

	case ADDRESS_ADD:
		do_address(res, IMSG_LISTEN_ADDRESS_ADD);
		break;
	case ADDRESS_DELETE:
		do_address(res, IMSG_LISTEN_ADDRESS_DELETE);
		break;
	case ADDRESS_LIST:
		do_address_list();
		break;

	case RELAY_ADD:
		do_relay(res, IMSG_RELAY_ADD);
		break;
	case RELAY_DELETE:
		do_relay(res, IMSG_RELAY_DELETE);
		break;
	case RELAY_LIST:
		do_relay_list(res->ipv4_1);
		break;

	case SHARED_NETWORK_ADD:
		do_shared_network(res, IMSG_SHARED_NETWORK_ADD);
		break;
	case SHARED_NETWORK_DELETE:
		do_shared_network(res, IMSG_SHARED_NETWORK_DELETE);
		break;
	case SHARED_NETWORK_LIST:
		do_shared_network_list();
		break;

	case SUBNET_ADD:
		do_subnet(res, IMSG_SUBNET_ADD);
		break;
	case SUBNET_DELETE:
		do_subnet(res, IMSG_SUBNET_DELETE);
		break;
	case SUBNET_LIST:
		do_subnet_list(res->string);
		break;
	case SUBNET_SHOW:
		do_subnet_show(res);
		break;
	case SUBNET_SET:
		do_subnet_set(res, IMSG_SUBNET_SET);
		break;
	case SUBNET_UNSET:
		do_subnet_set(res, IMSG_SUBNET_UNSET);
		break;

	case HOST_ADD:
		do_host(res, IMSG_HOST_ADD);
		break;
	case HOST_DELETE:
		do_host(res, IMSG_HOST_DELETE);
		break;
	case LEASES_DUMP:
		do_leases();
		break;
	case LEASE_RELEASE:
		do_lease_kill(res);
		break;

	case GROUP_CREATE:
		do_group_create(res);
		break;
	case GROUP_LIST:
		do_group_list();
		break;
	case GROUP_SET:
		do_group_set(res);
		break;
	case GROUP_UNSET:
		do_group_unset(res);
		break;

	case STATS:
		do_stats();
		break;

	default:
		return usage();
	}
	return (EXIT_SUCCESS);
}

#define	MAX_ARGUMENTS	15
static int
do_shell(void)
{
	struct parse_result *res;
	char word[256], *args[MAX_ARGUMENTS + 1];
	int i, delim;

	do {
		delim = ' ';
		if (isatty(fileno(stdin)))
			printf("dhcpctl> ");
		memset(args, 0, sizeof args);
		for (i = 0; i < MAX_ARGUMENTS && delim != '\n'; ++i) {
			if (scanf("%255s", word) == EOF)
				return fprintf(stderr, "<EOF>");
			delim = getchar();
			if ((args[i] = strndup(word, 255)) == NULL)
				return fprintf(stderr, "out of memory\n");
		}

		/* No need to free memory, we're going. */
		if (i == 1 && strcmp(args[0], "exit") == 0)
			break;

		if ((res = parse(i, args)) == NULL)
			return usage();
		action_switch(res, 1);

		while (i > 0)
			free(args[i--]);
	} while (res->action != SHELL);
	return (EXIT_SUCCESS);
}
#undef	MAX_ARGUMENTS

int
main(int argc, char *argv[])
{
	int			 sock, ch;
	struct parse_result	*res;
	struct passwd		*pw;

	if ((pw = getpwnam(UNPRIVILEGED_USER)) == NULL)
		err(1, "there isn't any user called " UNPRIVILEGED_USER);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		err(1, "can't drop privileges to " UNPRIVILEGED_USER);

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		size_t len;

		switch (ch) {
		case 's':
			len = strlcpy(sun.sun_path, optarg, sizeof sun.sun_path);
			if (len >= sizeof sun.sun_path)
				errx(1, "path too long: %s", optarg);
			sun.sun_len = len;
			break;
		default:
			return usage();
		}
	}
	argc -= optind;
	argv += optind;

	if ((res = parse(argc, argv)) == NULL)
		return usage();

	if ((sock = socket(PF_UNIX, SOCK_STREAM, AF_UNSPEC)) == -1)
		err(1, "socket(PF_UNIX)");
	if (connect(sock, (struct sockaddr *) &sun, sizeof sun) == -1)
		err(1, "connect(%s)", sun.sun_path);

	imsg_init(&ibuf, sock);
	action_switch(res, 0);

	tell_server_to_quit();
	close(sock);
	return (EXIT_SUCCESS);
}

