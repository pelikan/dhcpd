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
#include <stdlib.h>
#include <unistd.h>

#include "dhcpd.h"

/*
 * The administrator tells us ranges of addresses we're allowed to give
 * out to users.  We have to quickly figure out "some" free address for
 * each request, mark it as used and add a "struct lease" for it into a
 * RB tree sorted by the expiration time.  The worst reasonable case of
 * a sysadmin really picking on us would be the whole 10/8 range.  Then
 * potentially 16 million hosts (attackers trying to run us out of IPs)
 * compete and each of those 16 million packets will cause a lookup.
 */

#define RANGE_ALLOCATED(r, i)	(r->freemap[i / 8] & (1 << ((i) % 8)))
#define RANGE_ALLOCATE(r, i)	(r->freemap[i / 8] |= (1 << ((i) % 8)))
#define RANGE_FREE(r, i)	(r->freemap[i / 8] &= ~(1 << ((i) % 8)))

int
range_add(struct subnet *s, struct in_addr lo, struct in_addr hi)
{
	struct range *r, *t;
	size_t freemap, len;

	freemap = (ntohl(hi.s_addr) - ntohl(lo.s_addr) + 7) / 8;

	len = sizeof *r + freemap;
	if ((r = calloc(1, len)) == NULL)
		return (-1);

	r->lo = lo;
	r->hi = hi;

	if (s->range) {
		/* Find the closest range from the left, order by 'lo'. */
		for (t = s->range;
		    t->next && ntohl(t->next->lo.s_addr) <= ntohl(r->lo.s_addr);
		    t = t->next)
			;

		if (t == s->range) {
			/* If we're good from the right, r is a first range. */
			if (ntohl(r->hi.s_addr) < ntohl(t->lo.s_addr)) {
				s->range = r;
				r->next = t;
				return (0);
			}
		}

		if (t->next == NULL) {
			/* t begins before r->lo... how about t's hi end? */
			if (ntohl(r->lo.s_addr) > ntohl(t->hi.s_addr)) {
				t->next = r;
				return (0);
			}
			log_info("%s: last range overlaps our start at %s",
			    __func__, inet_ntoa(r->lo));
			goto fail;
		}

		/* t->next begins after r->lo... how about r->hi? */
		if (ntohl(t->next->lo.s_addr) <= ntohl(r->hi.s_addr)) {
			log_info("%s: next range starts before our end at %s",
			    __func__, inet_ntoa(r->hi));
			goto fail;
		}

		/* Connect the next range (non-overlapping from the right). */
		r->next = t->next;

		/* The whole t has to be before r->lo. */
		if (ntohl(t->hi.s_addr) > ntohl(r->lo.s_addr)) {
			log_info("%s: middle range ends after our start at %s",
			    __func__, inet_ntoa(r->lo));
			goto fail;
		}

		/* Connect this range (non-overlapping from the left). */
		t->next = r;
	}
	else
		s->range = r;
	return (0);
 fail:
	free(r);
	return (-1);
}

int
range_contains(struct range *r, struct in_addr a)
{
	u_int32_t cur = ntohl(a.s_addr);

	return (cur <= ntohl(r->hi.s_addr) && cur >= ntohl(r->lo.s_addr));
}

static void
range_copy(struct range *dst, struct range *src)
{
	int srcstart = (ntohl(dst->lo.s_addr) - ntohl(src->lo.s_addr));
	int i, total = (ntohl(dst->hi.s_addr) - ntohl(dst->lo.s_addr));

	for (i = 0; i < total; ++i) {
		if (RANGE_ALLOCATED(src, srcstart + i))
			RANGE_ALLOCATE(dst, i);
	}
}

/* Cut [lo, hi] from [r->lo, r->hi] -- split it into up to 2 ranges. */
static struct range *
range_delete_one(struct range *r, struct in_addr lo, struct in_addr hi)
{
	struct range *a = NULL, *b = NULL;
	size_t freemapa, freemapb;

	/* Clip it from the right. */
	if (ntohl(hi.s_addr) >= ntohl(r->hi.s_addr))
		hi = r->hi;
	else
		hi.s_addr = htonl(ntohl(hi.s_addr) + 1);

	/* Clip it from the left. */
	if (ntohl(lo.s_addr) <= ntohl(r->lo.s_addr))
		lo = r->lo;
	else
		lo.s_addr = htonl(ntohl(lo.s_addr) - 1);

	/* The boundaries don't touch this range. */
	if (ntohl(lo.s_addr) >= ntohl(r->hi.s_addr) ||
	    ntohl(hi.s_addr) <= ntohl(r->lo.s_addr))
		return (r);

	freemapa = (ntohl(lo.s_addr) - ntohl(r->lo.s_addr));
	freemapb = (ntohl(r->hi.s_addr) - ntohl(hi.s_addr));

	if (freemapa) {
		freemapa = (freemapa + 7) / 8;
		if ((a = calloc(1, sizeof *a + freemapa)) == NULL)
			goto fail;
		a->lo = r->lo;
		a->hi = lo;
		a->next = r->next;
		range_copy(a, r);
	}
	if (freemapb) {
		freemapb = (freemapb + 7) / 8;
		if ((b = calloc(1, sizeof *b + freemapb)) == NULL)
			goto fail;
		b->lo = hi;
		b->hi = r->hi;
		if (freemapa)
			a->next = b;
		b->next = r->next;
		range_copy(b, r);
	}

	/* Deleting the whole range means preserving the pointer to next. */
	if (freemapa == 0 && freemapb == 0)
		a = r->next;
	free(r);
	return freemapa ? a : freemapb ? b : a;
 fail:
	log_warnx("out of memory, shrinking ranges");
	free(a);
	free(b);
	return (NULL);
}

int
range_delete(struct subnet *s, struct in_addr lo, struct in_addr hi)
{
	struct range *r, *previous;

	/* If the first range got deleted, the next one may as well... */
	do {
		previous = s->range->next;
		r = s->range = range_delete_one(s->range, lo, hi);
	} while (r == previous);

	/* Delete until the end. */
	while (r && r->next) {
		r->next = range_delete_one(r->next, lo, hi);
		r = r->next;
	}
	return (0);
}

void
range_free(struct subnet *s, struct in_addr a)
{
	struct range *r;
	int i;

	r = s->range;
	while (r) {
		if (!range_contains(r, a)) {
			r = r->next;
			continue;
		}

		i = (ntohl(a.s_addr) - ntohl(r->lo.s_addr));

		if (ntohl(a.s_addr) > ntohl(r->hi.s_addr))
			fatalx("range_free: called with addr %s too large",
			    inet_ntoa(a));

		RANGE_FREE(r, i);
		return;
	}
	log_debug("range_free: address %s not in any range", inet_ntoa(a));
}

