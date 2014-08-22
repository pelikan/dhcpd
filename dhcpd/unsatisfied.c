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

#include <event.h>
#include <stdlib.h>
#include <string.h>

#include "dhcpd.h"

/*
 * When we don't have anything to give to clients, they'll just keep
 * repeating their questions.  My observed ratio from a relay was 120k
 * relayed DISCOVERS for 10k relayed REQUESTS.  To avoid filling up logs
 * with repetitive garbage, we keep track of unsatisfied clients as well.
 *
 * Currently there's no memory limit on them and we rely on libevent timers.
 */
struct unsatisfied {
	RB_ENTRY(unsatisfied)	 by_src;
	struct ether_addr	 mac;
	struct shared_network	*shared;

	struct event		 ev;
	time_t			 started;

	u_int64_t		 count;
};
RB_HEAD(unsatisfied_tree, unsatisfied) unsatisfied_tree;

static int
unsatisfied_src_cmp(struct unsatisfied *a, struct unsatisfied *b)
{
	int x;

	if ((x = shared_network_cmp(a->shared, b->shared)))
		return (x);
	return memcmp(&a->mac, &b->mac, ETHER_ADDR_LEN);
}

RB_GENERATE_STATIC(unsatisfied_tree, unsatisfied, by_src, unsatisfied_src_cmp)

static void
unsatisfied_expire(int sock, short ev, void *arg)
{
	struct unsatisfied *u = arg;
	time_t now;

	(void) sock; (void) ev;

	time(&now);
	log_info("%s: unsatisfied client %s asked us %llu times during %llu s",
	    u->shared->name, ether_ntoa(&u->mac), u->count, now - u->started);

	shared_network_free(u->shared);
	RB_REMOVE(unsatisfied_tree, &unsatisfied_tree, u);
	free(u);
}

void
unsatisfied_log(struct request *req, const char *where, char *preview)
{
	struct unsatisfied fake, *found;
	struct timeval delay = { UNSATISFIED_EXPIRY, 0 };

	fake.shared = req->shared;
	fake.mac = req->bootp->chaddr.ether;
	if ((found = RB_FIND(unsatisfied_tree, &unsatisfied_tree, &fake))) {
		evtimer_del(&found->ev);
		if (evtimer_add(&found->ev, &delay))
			goto freeit;
		++found->count;
		return;
	}

	if ((found = calloc(1, sizeof fake)) == NULL)
		goto doneit;

	time(&found->started);

	found->mac = fake.mac;
	found->shared = shared_network_use(fake.shared);
	RB_INSERT(unsatisfied_tree, &unsatisfied_tree, found);

	evtimer_set(&found->ev, unsatisfied_expire, found);
	if (evtimer_add(&found->ev, &delay)) {
 freeit:
		log_warn("%s: evtimer_add failed, freeing entry", __func__);
		unsatisfied_expire(-1, EV_TIMEOUT, found);
		return;
	}

	found->count = 1;
 doneit:
	log_info("%s: %s: new unsatisfied client %s%s", req->shared->name,
	    where, ether_ntoa(&req->bootp->chaddr.ether), preview);
}

void
unsatisfied_purge(void)
{
	struct unsatisfied *u, *uu;

	RB_FOREACH_SAFE(u, unsatisfied_tree, &unsatisfied_tree, uu) {
		evtimer_del(&u->ev);
		unsatisfied_expire(-1, EV_TIMEOUT, u);
	}
}
