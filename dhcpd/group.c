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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dhcpd.h"
#include "debug.h"

struct group_tree	groups;


int
group_cmp(struct group *a, struct group *b)
{
	return strcmp(a->name, b->name);
}

RB_GENERATE(group_tree, group, allgroups, group_cmp)

static struct group *
group_new(void)
{
	struct group *g;

	if ((g = calloc(1, sizeof(*g))) == NULL)
		return (NULL);

	snprintf(g->name, sizeof(g->name), "__anon__%08X",
	    arc4random_uniform(UINT_MAX));

	/*
	 * g->refcnt is zero, so the group exists on borrowed time and then
	 * goes after the first user wipes her bottom with it.
	 */
	return (g);
}

char *
group_create(struct ctl_group *ctl)
{
	struct group *g;

	if ((g = group_new()) == NULL)
		return "out of memory";

	strlcpy(g->name, ctl->name, sizeof(g->name));
	g->next = group_use(&default_group);

	if (RB_FIND(group_tree, &groups, g)) {
		free(g);
		return "group already there";
	}

	RB_INSERT(group_tree, &groups, g);

	log_debug("group created: %s", g->name);
	return NULL;
}

struct group *
group_use(struct group *g)
{
	REFCOUNT_DEBUG(g, g->name, g->refcnt);
	++g->refcnt;

	return g;
}

int
group_free(struct group *g)
{
	REFCOUNT_DEBUG(g, g->name, g->refcnt);
	if (--g->refcnt == 0) {
		RB_REMOVE(group_tree, &groups, g);
		group_free(g->next);
		free(g->filename);
		free(g->sname);
		free(g);
		return (0);
	}

	return (g->refcnt);
}

struct group *
group_find(char *name)
{
	struct group fake;

	strlcpy(fake.name, name, sizeof(fake.name));
	return RB_FIND(group_tree, &groups, &fake);
}

char *
group_set(struct ctl_group_settings *gs, size_t len)
{
	struct group *g, *parent, fake;
	int i;

	strlcpy(fake.name, gs->parent, sizeof(fake.name));
	if ((parent = RB_FIND(group_tree, &groups, &fake)) == NULL)
		return "no such parent group";

	strlcpy(fake.name, gs->name, sizeof(fake.name));
	if ((g = RB_FIND(group_tree, &groups, &fake)) == NULL)
		return "no such group";

	/* Reparenting needs to ensure we don't create a loop. */
	if (gs->flags & GROUP_WANT_PARENT) {
		struct group *temp = parent;

		if (strcmp(fake.name, "default") == 0)
			return "can't reparent default group";

		do {
			if (temp == g)
				return "ouroboros loop detected";
			temp = temp->next;
			/* default_group's parent is deliberately NULL */
		} while (temp && temp != &default_group);
	}

	len -= offsetof(struct ctl_group_settings, options);

	memset(&fake, 0, sizeof(fake));
	if (len > 2 && dhcp_options_parse(gs->options, len, fake.options) < 0)
		return "can't parse options";

	/* We need all of the options to be malloc'd, not just on stack. */
	for (i = 0; i < 256; ++i) {
		u_int8_t *temp;
		size_t optlen;

		if (fake.options[i] == NULL)
			continue;

		optlen = fake.options[i][0] + 1;
		if ((temp = malloc(optlen)) == NULL)
			goto fail;
		memcpy(temp, fake.options[i], optlen);
		fake.options[i] = temp;
	}

	/* All have been allocated successfully, move them into production. */
	for (i = 0; i < 256; ++i)
		if (fake.options[i]) {
			free(g->options[i]);
			g->options[i] = fake.options[i];
		}

	/* Take care of configuration with special needs. */
	if (gs->flags & GROUP_WANT_PARENT) {
		struct group *tmp = group_use(parent);

		group_free(g->next);
		g->next = tmp;
	}
	if (gs->flags & GROUP_WANT_NEXT_SERVER)
		g->next_server = gs->next_server;
	if (gs->flags & GROUP_WANT_FILENAME) {
		free(g->filename);
		g->filename = strndup(gs->filename, BOOTP_FILE);
	}
	if (gs->flags & GROUP_WANT_SNAME) {
		free(g->sname);
		g->sname = strndup(gs->sname, BOOTP_SNAME);
	}

	g->flags |= gs->flags | GROUP_MODIFIED;

	return NULL;

 fail:
	while (i > 0)
		free(fake.options[--i]);
	return "out of memory for options";
}

char *
group_unset(struct ctl_group_settings *gs, size_t len)
{
	struct group *g;
	size_t i;

	/* Don't allow the controller to mess with internals. */
	if (gs->flags & ~GROUP__CONTROLLER_FLAGS)
		return "you specified some non-controller flags";

	if ((g = group_find(gs->name)) == NULL)
		return "no such group";

	len -= offsetof(struct ctl_group_settings, options);

	/* Wipe all the options the controller wants us to. */
	for (i = 0; i < len; ++i) {
		free(g->options[gs->options[i]]);
		g->options[gs->options[i]] = NULL;
	}

	/* Take care of configuration with special needs. */
	if (gs->flags & GROUP_WANT_NEXT_SERVER)
		g->next_server.s_addr = INADDR_ANY;
	if (gs->flags & GROUP_WANT_FILENAME) {
		free(g->filename);
		g->filename = NULL;
	}
	if (gs->flags & GROUP_WANT_SNAME) {
		free(g->sname);
		g->sname = NULL;
	}

	g->flags &= ~gs->flags;

	return NULL;
}

static void
group_copyout(struct reply *reply, struct group *g)
{
	int i;

	for (i = 0; i < 256; ++i) {
		if (g->options[i] == NULL || reply->options[i] != NULL)
			continue;
		reply->options[i] = g->options[i];
	}

	if (reply->next_server == NULL && (g->flags & GROUP_WANT_NEXT_SERVER))
		reply->next_server = &g->next_server;
	if (reply->filename == NULL && (g->flags & GROUP_WANT_FILENAME))
		reply->filename = g->filename;
	if (reply->sname == NULL && (g->flags & GROUP_WANT_SNAME))
		reply->sname = g->sname;
}

void
group_copyout_chain(struct reply *reply, struct group *g)
{
	do {
		group_copyout(reply, g);
	} while ((g = g->next));
}

