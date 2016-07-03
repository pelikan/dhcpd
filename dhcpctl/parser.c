/*	$OpenBSD$ */

/*
 * Copyright (c) 2014 Martin Pelikan <pelikan@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#include <sys/socket.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vis.h>

#include "parser.h"

enum token_type {
	NOTOKEN,
	ENDTOKEN,
	KEYWORD,
	STRING,
	GROUP,
	INTERFACE,
	SUBNET,
	IPv4_FIRST,
	IPv4_SECOND,
	MAC,
	SYNTAX,
	OPT_TYPE,
	OPT_LENGTH,
	OPT_VALUE,

	/* We need to mark which ones did the user write. */
	FILENAME,
	NEXT_SERVER,
	PARENT,
	SNAME,
};

struct token {
	enum token_type		 type;
	const char		*keyword;
	int			 value;
	const struct token	*next;
};

/* group-name or a general-purpose string (usually shared_network name) */
static const struct token t_group_str[] = {
	{ GROUP,	"",		NONE,		NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_string[] = {
	{ STRING,	"",		NONE,		NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* optional ["group" t_group_str] */
static const struct token t_group_opt[] = {
	{ NOTOKEN,	"",		NONE,	NULL},
	{ KEYWORD, 	"group",	NONE,	t_group_str},
	{ ENDTOKEN,	"",		NONE,	NULL}
};

/* optional ["shared_network" t_string] */
static const struct token t_shared_net_opt[] = {
	{ NOTOKEN,	"",		NONE,	NULL},
	{ KEYWORD, 	"shared_network",	NONE,	t_string},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* ["group" t_group_str ["shared_network" t_string]] (below forwards) */
/* ["shared_network" t_string ["group" t_group_str]] (above backwards) */
static const struct token t_group_s_opt[] = {
	{ GROUP,	"",		NONE,		t_shared_net_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_string_g_opt[] = {
	{ STRING,	"",		NONE,		t_group_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_shared_net_group_opt[] = {
	{ NOTOKEN,	"",		NONE,	NULL},
	{ KEYWORD, 	"group",		NONE,	t_group_s_opt},
	{ KEYWORD, 	"shared_network",	NONE,	t_string_g_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* shared_network main menu */
static const struct token t_shared_network[] = {
	{ NOTOKEN,	"",		NONE,	NULL},
	{ KEYWORD,	"add",		SHARED_NETWORK_ADD,	t_string},
	{ KEYWORD,	"delete",	SHARED_NETWORK_DELETE,	t_string},
	{ KEYWORD,	"list",		SHARED_NETWORK_LIST,	NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_range_hi[] = {
	{ NOTOKEN,	"",		NONE,		NULL},
	{ IPv4_SECOND,	"",		NONE,		t_shared_net_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_range_lo[] = {
	{ IPv4_FIRST,	"",		NONE,		t_range_hi},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_subnet_range[] = {
	{ NOTOKEN,	"",		NONE,		NULL},
	{ KEYWORD,	"range",	NONE,		t_range_lo},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* subnet can be added to non-default shared_network with a non-default group */
static const struct token t_subnet_add[] = {
	{ SUBNET,	"",		NONE,		t_shared_net_group_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
/* subnet can be deleted/shown from some shared_network, no need for groups */
static const struct token t_subnet_delete[] = {
	{ SUBNET,	"",		NONE,		t_shared_net_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_subnet_set[] = {
	{ SUBNET,	"",		NONE,		t_subnet_range},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* subnet main menu */
static const struct token t_subnet[] = {
	{ NOTOKEN,	"",		NONE,	NULL},
	{ KEYWORD,	"add",		SUBNET_ADD,	t_subnet_add},
	{ KEYWORD,	"delete",	SUBNET_DELETE,	t_subnet_delete},
	{ KEYWORD,	"list",		SUBNET_LIST,	t_shared_net_opt},
	{ KEYWORD,	"set",		SUBNET_SET,	t_subnet_set},
	{ KEYWORD,	"show",		SUBNET_SHOW,	t_subnet_delete},
	{ KEYWORD,	"unset",	SUBNET_UNSET,	t_subnet_set},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* group creation and parameter (TLV or otherwise XXX) settings */
extern const struct token t_group_opts[];
static const struct token t_g_parent[] = {
	{ PARENT,	"",		NONE,		t_group_opts},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_g_filename[] = {
	{ FILENAME,	"",		NONE,		t_group_opts},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_g_sname[] = {
	{ SNAME,	"",		NONE,		t_group_opts},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_g_nextserver[] = {
	{ NEXT_SERVER,	"",		NONE,		t_group_opts},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_group_create[] = {
	{ GROUP,	"",		NONE,		NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_group_v[] = {
	{ OPT_VALUE,	"",		NONE,		NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_group_lv[] = {
	{ OPT_LENGTH,	"",		NONE,		t_group_v},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

const struct token t_group_opts[] = {
	{ NOTOKEN,	"",		NONE,		NULL},
	{ KEYWORD,	"parent",	NONE,		t_g_parent},
	{ KEYWORD,	"filename",	NONE,		t_g_filename},
	{ KEYWORD,	"server-name",	NONE,		t_g_sname},
	{ KEYWORD,	"next-server",	NONE,		t_g_nextserver},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
const struct token t_group_tlv_[] = {
	{ OPT_TYPE,	"",		NONE,		t_group_lv},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
const struct token t_group_tlv[] = {
	{ SYNTAX,	"",		NONE,		t_group_tlv_},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_group_set[] = {
	{ GROUP,	"",		NONE,		t_group_opts},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_group_set_tlv[] = {
	{ GROUP,	"",		NONE,		t_group_tlv},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_group_unset_tlv[] = {
	{ GROUP,	"",		NONE,		t_group_lv},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* group main menu */
static const struct token t_group[] = {
	{ NOTOKEN,	"",		NONE,		NULL},
	{ KEYWORD,	"create",	GROUP_CREATE,	t_group_create},
	{ KEYWORD,	"set",		GROUP_SET,	t_group_set},
	{ KEYWORD,	"unset",	GROUP_UNSET,	NULL /* XXX */},
	{ KEYWORD,	"tlv-set",	GROUP_SET,	t_group_set_tlv},
	{ KEYWORD,	"tlv-unset",	GROUP_UNSET,	t_group_unset_tlv},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* host can specify a group specific to it */
static const struct token t_host_mac[] = {
	{ MAC,		"",		NONE,		t_group_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_host_add[] = {
	{ IPv4_FIRST,	"",		NONE,		t_host_mac},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_host_del[] = {
	{ IPv4_FIRST,	"",		NONE,		NULL},
	{ MAC,		"",		NONE,		t_shared_net_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* host main menu */
static const struct token t_host[] = {
	{ NOTOKEN,	"",		NONE,	NULL},
	{ KEYWORD,	"add",		HOST_ADD,	t_host_add},
	{ KEYWORD,	"delete",	HOST_DELETE,	t_host_del},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* interfaces and addresses can have shared_networks to them */
static const struct token t_interface[] = {
	{ INTERFACE,	"",		NONE,		t_shared_net_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_interfaces[] = {
	{ NOTOKEN,	"",		NONE,		NULL},
	{ KEYWORD,	"add",		INTERFACE_ADD,		t_interface},
	{ KEYWORD,	"delete",	INTERFACE_DELETE,	t_interface},
	{ KEYWORD,	"list",		INTERFACE_LIST,	NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_address[] = {
	{ IPv4_FIRST,	"",		NONE,		t_shared_net_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_addresses[] = {
	{ NOTOKEN,	"",		NONE,		NULL},
	{ KEYWORD,	"add",		ADDRESS_ADD,	t_address},
	{ KEYWORD,	"delete",	ADDRESS_DELETE,	t_address},
	{ KEYWORD,	"list",		ADDRESS_LIST,	NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* relay <relay-ip> to <listen-address> [shared_network <shared-network>] */
/* relay <relay-ip> stop to <listen-address> [shared_network <shared-net>] */
static const struct token t_relay_dst[] = {
	{ IPv4_SECOND,	"",		NONE,		t_shared_net_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_relay_to[] = {
	{ KEYWORD,	"to",		NONE,		t_relay_dst},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_relay_stop_opt[] = {
	{ KEYWORD,	"to",		RELAY_ADD,	t_relay_dst},
	{ KEYWORD,	"stop",		RELAY_DELETE,	t_relay_to},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
/* relay list [<listen-address>] */
static const struct token t_ipv4_1_opt[] = {
	{ NOTOKEN,	"",		NONE,		NULL},
	{ IPv4_FIRST,	"",		NONE,		NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};
static const struct token t_relay[] = {
	{ IPv4_FIRST,	"",		NONE,		t_relay_stop_opt},
	{ KEYWORD,	"any",		NONE,		t_relay_stop_opt},
	{ KEYWORD,	"list",		RELAY_LIST,	t_ipv4_1_opt},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* lease [release <MAC> shared_network_opt] */
static const struct token t_lease[] = {
	{ NOTOKEN,	"",		NONE,		NULL},
	{ KEYWORD,	"release",	LEASE_RELEASE,	t_host_del},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

/* real main menu */
static const struct token t_main[] = {
	{ KEYWORD,	"group",	GROUP_LIST,	t_group},
	{ KEYWORD,	"host",			NONE,	t_host},
	{ KEYWORD,	"interface",		NONE,	t_interfaces},
	{ KEYWORD,	"address",		NONE,	t_addresses},
	{ KEYWORD,	"relay",		NONE,	t_relay},
	{ KEYWORD,	"shared_network",	NONE,	t_shared_network},
	{ KEYWORD,	"subnet",		NONE,	t_subnet},
	{ KEYWORD,	"lease",	LEASES_DUMP,	t_lease},
	{ KEYWORD,	"shell",	SHELL,		NULL},
	{ KEYWORD,	"statistics",	STATS,		NULL},
	{ ENDTOKEN,	"",			NONE,	NULL}
};

static struct parse_result	res;

const struct token	*match_token(int *argc, char **argv[],
			    const struct token []);
void			 show_valid_args(const struct token []);

struct parse_result *
parse(int argc, char *argv[])
{
	const struct token	*table = t_main;
	const struct token	*match;

	bzero(&res, sizeof(res));

	/* may be overwritten by shared_network_opt or group_opt */
	strlcpy(res.string, "default", sizeof(res.string));
	strlcpy(res.group, "default", sizeof(res.group));

	while (argc >= 0) {
		if ((match = match_token(&argc, &argv, table)) == NULL) {
			fprintf(stderr, "valid commands/args:\n");
			show_valid_args(table);
			return (NULL);
		}

		argc--;
		argv++;

		if (match->type == NOTOKEN || match->next == NULL)
			break;

		table = match->next;
	}

	if (argc > 0) {
		fprintf(stderr, "superfluous argument: %s\n", argv[0]);
		return (NULL);
	}

	return (&res);
}

static int
parse_subnet(struct parse_result *tgt, const char *word)
{
	char *slash, ipv4[INET_ADDRSTRLEN];

	if ((slash = strchr(word, '/')) == NULL)
		return 0;

	if (slash - word > (long) sizeof(ipv4))
		return 0;

	tgt->prefixlen = atoi(slash + 1);

	memset(&ipv4, 0, sizeof(ipv4));
	memcpy(ipv4, word, slash - word);
	return inet_aton(ipv4, &tgt->network);
}

static __dead void
bad_ip_list(const char *str)
{
	char s[64];
	strnvis(s, str, sizeof s, VIS_SAFE | VIS_NL);
	errx(1, "invalid input '%s' from an IP address list", s);
}

static char *
delimiter(char *str)
{
	while (*str != '\0' && *str != '\n') {
		switch (*str) {
		case ',':
		case ' ':
		case '\t':
			return (str);
		case '.':
			++str;
			continue;
		default:
			if (*str >= '0' && *str <= '9')
				++str;
			else
				bad_ip_list(str);
		}
	}
	return (NULL);
}

void
parse_ip_list(void)
{
	struct in_addr a, *nlist;
	char *delim, *p = (char *)res.opt_value;

	res.ipv4_list_cnt = 0;
	do {
		delim = delimiter(p);
		if (delim) {
			delim[0] = '\0';
			++delim;
		}
		if (inet_aton(p, &a) == 0)
			bad_ip_list(p);
		++res.ipv4_list_cnt;
		if ((nlist = reallocarray(res.ipv4_list, res.ipv4_list_cnt,
		    sizeof *res.ipv4_list)) == NULL)
			err(1, "out of memory");
		res.ipv4_list = nlist;
		memcpy(nlist + res.ipv4_list_cnt - 1, &a, sizeof a);
		p = delim;
	} while (p != NULL);
}

const struct token *
match_token(int *argc, char **argv[], const struct token table[])
{
	u_int			 i, match;
	const struct token	*t = NULL;
	const char		*word = *argv[0];
	struct ether_addr	*mac;

	(void) argc;
	match = 0;

	for (i = 0; table[i].type != ENDTOKEN; i++) {
		switch (table[i].type) {
		case NOTOKEN:
			if (word == NULL || strlen(word) == 0) {
				match++;
				t = &table[i];
			}
			break;
		case KEYWORD:
			if (word != NULL && strncmp(word, table[i].keyword,
			    strlen(word)) == 0) {
				match++;
				t = &table[i];
				if (t->value)
					res.action = t->value;
			}
			break;
		case INTERFACE:
			if (word == NULL || strlen(word) > IF_NAMESIZE) {
				fprintf(stderr, "interface name too long\n");
				break;
			}
			match++;
			t = &table[i];
			strlcpy(res.interface, word, sizeof(res.interface));
			break;
		case PARENT:
			res.flags |= GROUP_WANT_PARENT;
			/* FALLTHROUGH */
		case SYNTAX:
			if (word != NULL) {
				match++;
				t = &table[i];
				strlcpy(res.syntax, word, sizeof(res.syntax));
			}
			break;
		case STRING:
			if (word != NULL) {
				match++;
				t = &table[i];
				strlcpy(res.string, word, sizeof(res.string));
			}
			break;
		case FILENAME:
			if (word != NULL) {
				match++;
				t = &table[i];
				strlcpy(res.filename, word, BOOTP_FILE);
				res.flags |= GROUP_WANT_FILENAME;
			}
			break;
		case SNAME:
			if (word != NULL) {
				match++;
				t = &table[i];
				strlcpy(res.sname, word, BOOTP_SNAME);
				res.flags |= GROUP_WANT_SNAME;
			}
			break;
		case GROUP:
			if (word != NULL) {
				match++;
				t = &table[i];
				strlcpy(res.group, word, sizeof(res.group));
			}
			break;
		case SUBNET:
			if (word != NULL && parse_subnet(&res, word)) {
				match++;
				t = &table[i];
			}
			break;
		case NEXT_SERVER:
			res.flags |= GROUP_WANT_NEXT_SERVER;
			/* FALLTHROUGH */
		case IPv4_FIRST:
			if (word != NULL && inet_aton(word, &res.ipv4_1)) {
				match++;
				t = &table[i];
			}
			break;
		case IPv4_SECOND:
			if (word != NULL && inet_aton(word, &res.ipv4_2)) {
				match++;
				t = &table[i];
			}
			break;
		case MAC:
			if (word != NULL && (mac = ether_aton(word))) {
				match++;
				t = &table[i];
				memcpy(&res.mac, mac, ETHER_ADDR_LEN);
			}
			break;
		case OPT_TYPE:
			res.opt_type = atoi(word);
			if (res.opt_type > 0 && res.opt_type < 255) {
				match++;
				t = &table[i];
			}
			break;
		case OPT_LENGTH:
			res.opt_length = atoi(word);
			if (res.opt_length > 0 && res.opt_length < 255) {
				match++;
				t = &table[i];
			}
			break;
		case OPT_VALUE:
			memcpy(res.opt_value, word, res.opt_length);
			match++;
			t = &table[i];
			break;
		case ENDTOKEN:
			break;
		}
	}

	if (match != 1) {
		if (word == NULL)
			fprintf(stderr, "missing argument:\n");
		else if (match > 1)
			fprintf(stderr, "ambiguous argument: %s\n", word);
		else if (match < 1)
			fprintf(stderr, "unknown argument: %s\n", word);
		return (NULL);
	}

	return (t);
}

void
show_valid_args(const struct token table[])
{
	int	i;

	for (i = 0; table[i].type != ENDTOKEN; i++) {
		switch (table[i].type) {
		case NOTOKEN:
			fprintf(stderr, "  <newline>\n");
			break;
		case KEYWORD:
			fprintf(stderr, "  %s\n", table[i].keyword);
			break;
		case PARENT:
		case STRING:
		case FILENAME:
		case SNAME:
			fprintf(stderr, "  <string>\n");
			break;
		case SYNTAX:
			fprintf(stderr, "  (bytes|IP|IP-list)\n");
			break;
		case GROUP:
			fprintf(stderr, "  <group-name>\n");
			break;
		case INTERFACE:
			fprintf(stderr, "  <interface-name>\n");
			break;
		case SUBNET:
			fprintf(stderr, "  <IPv4-address>/<prefix-len>\n");
			break;
		case NEXT_SERVER:
		case IPv4_FIRST:
		case IPv4_SECOND:
			fprintf(stderr, "  <IPv4-address>\n");
			break;
		case MAC:
			fprintf(stderr, "  <MAC:address:with:colons>\n");
			break;
		case OPT_TYPE:
			fprintf(stderr, "  <type length value>\n");
			break;
		case OPT_LENGTH:
			fprintf(stderr, "  <length value>\n");
			break;
		case OPT_VALUE:
			fprintf(stderr, "  <value>\n");
			break;
		case ENDTOKEN:
			break;
		}
	}
}
