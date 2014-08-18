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

#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dhcpd.h"

struct ctl_conn {
	LIST_ENTRY(ctl_conn)	controllers;
	int			sock;
	struct event		ev;
	struct imsgbuf		ibuf;

	union {
		struct sockaddr_storage ss;
		struct sockaddr sa;
	} addr;
	socklen_t addrlen;
};

LIST_HEAD(, ctl_conn) all_controllers = LIST_HEAD_INITIALIZER(all_controllers);


size_t
controllers(void)
{
	size_t cnt = 0;
	struct ctl_conn *ctl;

	LIST_FOREACH(ctl, &all_controllers, controllers)
		++cnt;
	return (cnt);
}

static int
fail(struct ctl_conn *ctl, const char *msg)
{
	u_int16_t len = strnlen(msg, ERR_BUF_SIZE);

	imsg_compose(&ctl->ibuf, IMSG_ERROR, 0, 0, -1, msg, len);
	if (imsg_flush(&ctl->ibuf))
		log_warn("imsg_flush");
	return (EXIT_FAILURE);
}

static int
control_list_shared_networks(struct ctl_conn *ctl)
{
	struct shared_network *s;
	struct ctl_shared *buf;
	size_t count = 0, pos = 0, len;

	RB_FOREACH(s, shared_network_tree, &shared_networks)
		count++;

	if ((buf = calloc(count, sizeof *buf)) == NULL)
		return fail(ctl, "out of memory");
	len = count * sizeof *buf;

	RB_FOREACH(s, shared_network_tree, &shared_networks) {
		strlcpy(buf[pos].name, s->name, sizeof buf[pos].name);
		++pos;
	}
	assert(pos == count);

	imsg_compose(&ctl->ibuf, IMSG_SHARED_NETWORK_LIST, 0, 0, -1, buf, len);
	if (imsg_flush(&ctl->ibuf))
		log_warn("imsg_flush");
	free(buf);
	return (EXIT_SUCCESS);
}

static int
control_list_subnets(struct ctl_conn *ctl, struct ctl_subnet *imsgdata)
{
	struct subnet *s;
	struct ctl_subnet *buf;
	size_t count = 0, pos = 0, len;
	struct shared_network fake_shared, *where;

	memset(&fake_shared, 0, sizeof fake_shared);
	fake_shared.name = imsgdata->shared;

	where = RB_FIND(shared_network_tree, &shared_networks, &fake_shared);
	if (where == NULL)
		return fail(ctl, "shared_network not found");

	RB_FOREACH(s, subnet_tree, &where->subnets)
		if (s->shared == where)
			count++;

	if ((buf = calloc(count, sizeof *buf)) == NULL)
		return fail(ctl, "out of memory");
	len = count * sizeof *buf;

	RB_FOREACH(s, subnet_tree, &where->subnets)
		if (s->shared == where) {
			buf[pos].network = s->network;
			buf[pos].prefixlen = s->prefixlen;
			strlcpy(buf[pos].shared, where->name,
			    sizeof buf[pos].shared);
			++pos;
		}

	assert(pos == count);

	imsg_compose(&ctl->ibuf, IMSG_SUBNET_LIST, 0, 0, -1, buf, len);
	if (imsg_flush(&ctl->ibuf))
		log_warn("imsg_flush");
	free(buf);
	return (EXIT_SUCCESS);
}

static int
control_show_subnet(struct ctl_conn *ctl, struct ctl_subnet *imsgdata)
{
	struct host *h;
	struct range *r;
	struct subnet *s;
	struct ctl_host *hbuf;
	struct ctl_subnet_settings *sbuf;
	size_t count = 0, pos = 0, len;
	const size_t imsglim = MAX_IMSGSIZE / sizeof *hbuf;

	if ((s = subnet_find(imsgdata->network, imsgdata->shared)) == NULL)
		return fail(ctl, "subnet not found");

	r = s->range;
	while (r)
		++count, r = r->next;

	if ((sbuf = calloc(count, sizeof *sbuf)) == NULL)
		return fail(ctl, "out of memory");
	len = count * sizeof *sbuf;

	for (r = s->range; r; r = r->next) {
		sbuf[pos].range_lo = r->lo;
		sbuf[pos].range_hi = r->hi;
		++pos;
	}

	assert(pos == count);

	imsg_compose(&ctl->ibuf, IMSG_SUBNET_SET, 0, 0, -1, sbuf, len);
	if (imsg_flush(&ctl->ibuf))
		log_warn("imsg_flush");
	free(sbuf);

	count = pos = 0;
	RB_FOREACH(h, host_ipv4_tree, &s->hosts)
		++count;

	if ((hbuf = calloc(MIN(count, imsglim), sizeof *hbuf)) == NULL)
		return fail(ctl, "out of memory");

	RB_FOREACH(h, host_ipv4_tree, &s->hosts) {
		hbuf[pos].ip = h->address;
		memcpy(&hbuf[pos].mac, &h->mac, ETHER_ADDR_LEN);
		strlcpy(hbuf[pos].shared, s->shared->name,
		    sizeof hbuf[pos].shared);
		if (++pos == imsglim) {
			imsg_compose(&ctl->ibuf, IMSG_SUBNET_SHOW, 0, 0, -1,
			    hbuf, pos * sizeof *hbuf);
			while (imsg_flush(&ctl->ibuf))
				;
			pos = 0;
		}
	}

	if (pos) {
		imsg_compose(&ctl->ibuf, IMSG_SUBNET_SHOW, 0, 0, -1,
		    hbuf, pos * sizeof *hbuf);
		while (imsg_flush(&ctl->ibuf))
			;
	}
	free(hbuf);
	return (EXIT_SUCCESS);
}

static int
control_dump_leases(struct ctl_conn *ctl)
{
	struct ctl_lease *buf = NULL;
	ssize_t count, len = 0, done;
	const ssize_t chunk = MAX_IMSGSIZE / sizeof *buf;

	if ((count = leases_dump(&buf, &len)) == -1)
		return fail(ctl, "leases_dump failed");

	for (done = 0; done < count; done += chunk) {
		size_t xmit_now = MIN(count - done, chunk);

		imsg_compose(&ctl->ibuf, IMSG_LEASES_DUMP, 0, 0, -1,
		    buf + done, xmit_now * sizeof *buf);
		while (imsg_flush(&ctl->ibuf))
			;
	}
	free(buf);
	return (EXIT_SUCCESS);
}

static int
control_list_groups(struct ctl_conn *ctl)
{
	struct group *g;
	struct ctl_group *buf;
	size_t count = 0, pos = 0, len;

	RB_FOREACH(g, group_tree, &groups)
		++count;

	log_debug("listing %zu groups", count);
	if ((buf = calloc(count, sizeof *buf)) == NULL)
		return fail(ctl, "out of memory");
	len = count * sizeof *buf;

	RB_FOREACH(g, group_tree, &groups) {
		strlcpy(buf[pos].name, g->name, sizeof buf[pos].name);

		/* XXX Print next groups in chain? */
		++pos;
	}

	assert(pos == count);

	imsg_compose(&ctl->ibuf, IMSG_GROUP_LIST, 0, 0, -1, buf, len);
	if (imsg_flush(&ctl->ibuf))
		log_warn("imsg_flush");
	free(buf);
	return (EXIT_SUCCESS);
}

static int
control_list_interfaces(struct ctl_conn *ctl)
{
	ssize_t count, len = 0;
	struct ctl_interface *buf = NULL;

	if ((count = interfaces_dump(&buf, &len)) == -1)
		return fail(ctl, "interfaces_dump failed");
	len = count * sizeof *buf;

	imsg_compose(&ctl->ibuf, IMSG_LISTEN_INTERFACE_LIST, 0, 0, -1, buf,len);
	if (imsg_flush(&ctl->ibuf))
		log_warn("imsg_flush");
	free(buf);
	return (EXIT_SUCCESS);
}

static int
control_list_addresses(struct ctl_conn *ctl)
{
	ssize_t count, len = 0;
	struct ctl_address *buf = NULL;

	if ((count = ipv4_addr_dump(&buf, &len)) == -1)
		return fail(ctl, "ipv4_addr_dump failed");
	len = count * sizeof *buf;

	imsg_compose(&ctl->ibuf, IMSG_LISTEN_ADDRESS_LIST, 0, 0, -1, buf, len);
	if (imsg_flush(&ctl->ibuf))
		log_warn("imsg_flush");
	free(buf);
	return (EXIT_SUCCESS);
}

static int
control_list_relays(struct ctl_conn *ctl, struct in_addr *ip)
{
	struct ctl_relay *buf = NULL;
	ssize_t count = 0, len = 0;
	char *ret;

	log_warnx("listing relays at... %s", inet_ntoa(*ip));
	ret = relays_dump(&buf, &len, &count, *ip);
	if (ret)
		return fail(ctl, ret);
	len = count * sizeof *buf;

	imsg_compose(&ctl->ibuf, IMSG_RELAY_LIST, 0, 0, -1, buf, len);
	if (imsg_flush(&ctl->ibuf))
		log_warn("imsg_flush");

	free(buf);
	return (EXIT_SUCCESS);
}

static int
control_statistics_unknown_options(struct ctl_conn *ctl)
{
	extern u_int64_t stats__unknown_requested_options[256];
	extern u_int64_t stats__unknown_received_options[256];
	struct iovec iov[3];

	iov[0].iov_base = stats__unknown_requested_options;
	iov[1].iov_base = stats__unknown_received_options;
	iov[2].iov_base = stats;
	iov[0].iov_len = iov[1].iov_len = 256 * sizeof(u_int64_t);
	iov[2].iov_len = STATS__MAXIMUM * sizeof(u_int64_t);

	imsg_composev(&ctl->ibuf, IMSG_STATS, 0, 0, -1, iov, 3);
	while (imsg_flush(&ctl->ibuf))
		;
	return (EXIT_SUCCESS);
}


int
control_init(char *path, uid_t uid, gid_t gid)
{
	struct sockaddr_un sun = { sizeof PATH_CTLSOCK, AF_UNIX, PATH_CTLSOCK };
	int s;

	if (path) {
		size_t len = strlcpy(sun.sun_path, path, sizeof sun.sun_path);
		if (len >= sizeof sun.sun_path) {
			warnx("%s: path too long: %s", __func__, path);
			return (-1);
		}
		sun.sun_len = len;
		sun.sun_family = AF_UNIX;
	}
	else
		path = sun.sun_path;

	if (unlink(path) == -1 && errno != ENOENT) {
		warn("%s: unlink(2): %s", __func__, path);
		return (-1);
	}

	if ((s = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC)) == -1) {
		warn("%s: socket(2) AF_UNIX", __func__);
		return (-1);
	}

	if (bind(s, (struct sockaddr *) &sun, sizeof sun) == -1) {
		warn("%s: bind(2): %s", __func__, path);
		goto fail;
	}

	if (chown(path, uid, gid) == -1) {
		warn("%s: chown(2): %s " UNPRIVILEGED_USER, __func__, path);
		goto fail;
	}

	if (chmod(path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) == -1) {
		warn("%s: chmod(2) 660: %s", __func__, path);
		goto fail;
	}

	if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
		warn("%s: fcntl(2) O_NONBLOCK", __func__);
		goto fail;
	}

	if (listen(s, 5) == -1) {
		warn("%s: listen(2)", __func__);
		goto fail;
	}

	return (s);

 fail:
	close(s);
	return (-1);
}

void
control_accept(int listener, short ev, void *arg)
{
	struct ctl_conn *ctl;

	(void) ev;
	(void) arg;

	if ((ctl = calloc(1, sizeof *ctl)) == NULL) {
		log_warn("%s: out of memory", __func__);
		sleep(1);
		return;
	}

	ctl->sock = accept(listener, &ctl->addr.sa, &ctl->addrlen);
	if (ctl->sock == -1) {
		log_warn("accept(2)");
		goto fail;
	}

	if (fcntl(ctl->sock, F_SETFL, O_NONBLOCK) == -1) {
		log_warn("%s: fcntl(2) O_NONBLOCK", __func__);
		goto fail;
	}

	event_set(&ctl->ev, ctl->sock, EV_READ, control_dispatch, ctl);
	if (event_add(&ctl->ev, NULL))
		goto fail;

	imsg_init(&ctl->ibuf, ctl->sock);
	LIST_INSERT_HEAD(&all_controllers, ctl, controllers);

	return;
 fail:
	close(ctl->sock);
	free(ctl);
}

static struct ctl_conn *
control_connbyfd(int sock)
{
	struct ctl_conn *ctl;

	LIST_FOREACH(ctl, &all_controllers, controllers)
		if (sock == ctl->sock)
			return (ctl);

	log_warnx("%s: socket %d not found in controllers", __func__, sock);
	fatalx("non-existing controller");
	return (NULL);	/* NOTREACHED */
}

static void
control_finish(struct ctl_conn *ctl)
{
	if (close(ctl->sock) == -1)
		log_warn("close(2) on control socket fd %d", ctl->sock);
	event_del(&ctl->ev);
	LIST_REMOVE(ctl, controllers);
	free(ctl);
}

void
control_close(int sock)
{
	control_finish(control_connbyfd(sock));
}

void
control_dispatch(int sock, short ev, void *arg)
{
	struct ctl_conn *ctl = arg;
	struct imsg	 imsg;
	ssize_t		 n;
	char		*errstr = NULL;

	assert(ev == EV_READ);
	assert(ctl->ibuf.fd == sock);

	if ((n = imsg_read(&ctl->ibuf)) == -1) {
		log_warn("imsg_read(3)");
		return;
	}

	while ((n = imsg_get(&ctl->ibuf, &imsg)) > 0) {
		size_t pld_len = imsg.hdr.len - IMSG_HEADER_SIZE;

		errstr = NULL;
		switch (imsg.hdr.type) {
		case IMSG_DONE:
			goto finish;

		case IMSG_SHARED_NETWORK_ADD:
			if (pld_len != sizeof(struct ctl_shared))
				goto fail;
			if ((errstr = shared_network_add(imsg.data)))
				goto fail;
			break;
		case IMSG_SHARED_NETWORK_DELETE:
			if (pld_len != sizeof(struct ctl_shared))
				goto fail;
			if ((errstr = shared_network_delete(imsg.data)))
				goto fail;
			break;
		case IMSG_SHARED_NETWORK_LIST:
			control_list_shared_networks(ctl);
			break;

		case IMSG_SUBNET_ADD:
			if (pld_len != sizeof(struct ctl_subnet))
				goto fail;
			if ((errstr = subnet_add(imsg.data)))
				goto fail;
			break;
		case IMSG_SUBNET_DELETE:
			if (pld_len != sizeof(struct ctl_subnet))
				goto fail;
			if ((errstr = subnet_delete(imsg.data)))
				goto fail;
			break;
		case IMSG_SUBNET_LIST:
			control_list_subnets(ctl, imsg.data);
			break;
		case IMSG_SUBNET_SHOW:
			control_show_subnet(ctl, imsg.data);
			break;
		case IMSG_SUBNET_SET:
			if (pld_len != sizeof(struct ctl_subnet_settings))
				goto fail;
			if ((errstr = subnet_set(imsg.data)))
				goto fail;
			break;
		case IMSG_SUBNET_UNSET:
			if (pld_len != sizeof(struct ctl_subnet_settings))
				goto fail;
			if ((errstr = subnet_unset(imsg.data)))
				goto fail;
			break;

		case IMSG_HOST_ADD:
			if (pld_len != sizeof(struct ctl_host))
				goto fail;
			if ((errstr = host_add(imsg.data)))
				goto fail;
			break;
		case IMSG_HOST_DELETE:
			if (pld_len != sizeof(struct ctl_host))
				goto fail;
			if ((errstr = host_delete(imsg.data)))
				goto fail;
			break;
		case IMSG_LEASES_DUMP:
			control_dump_leases(ctl);
			break;
		case IMSG_LEASE_RELEASE:
			if (pld_len != sizeof(struct ctl_lease))
				goto fail;
			if ((errstr = lease_kill(imsg.data)))
				goto fail;
			break;

		case IMSG_GROUP_CREATE:
			if (pld_len != sizeof(struct ctl_group))
				goto fail;
			if ((errstr = group_create(imsg.data)))
				goto fail;
			break;
		case IMSG_GROUP_LIST:
			control_list_groups(ctl);
			break;
		case IMSG_GROUP_SET:
			if (pld_len <= offsetof(struct ctl_group_settings,
			    options))
				goto fail;
			if ((errstr = group_set(imsg.data, pld_len)))
				goto fail;
			break;
		case IMSG_GROUP_UNSET:
			if (pld_len <= offsetof(struct ctl_group_settings,
			    options))
				goto fail;
			if ((errstr = group_unset(imsg.data, pld_len)))
				goto fail;
			break;

		case IMSG_LISTEN_INTERFACE_ADD:
			if (pld_len != sizeof(struct ctl_interface))
				goto fail;
			if ((errstr = interface_add(imsg.data)))
				goto fail;
			break;
		case IMSG_LISTEN_INTERFACE_DELETE:
			if (pld_len != sizeof(struct ctl_interface))
				goto fail;
			if ((errstr = interface_delete(imsg.data)))
				goto fail;
			break;
		case IMSG_LISTEN_INTERFACE_LIST:
			control_list_interfaces(ctl);
			break;

		case IMSG_LISTEN_ADDRESS_ADD:
			if (pld_len != sizeof(struct ctl_address))
				goto fail;
			if ((errstr = ipv4_addr_add(imsg.data)))
				goto fail;
			break;
		case IMSG_LISTEN_ADDRESS_DELETE:
			if (pld_len != sizeof(struct ctl_address))
				goto fail;
			if ((errstr = ipv4_addr_delete(imsg.data)))
				goto fail;
			break;
		case IMSG_LISTEN_ADDRESS_LIST:
			control_list_addresses(ctl);
			break;

		case IMSG_RELAY_ADD:
			if (pld_len != sizeof(struct ctl_relay))
				goto fail;
			if ((errstr = relay_on(imsg.data)))
				goto fail;
			break;
		case IMSG_RELAY_DELETE:
			if (pld_len != sizeof(struct ctl_relay))
				goto fail;
			if ((errstr = relay_off(imsg.data)))
				goto fail;
			break;
		case IMSG_RELAY_LIST:
			if (pld_len != sizeof(struct in_addr))
				goto fail;
			control_list_relays(ctl, imsg.data);
			break;

		case IMSG_STATS:
			control_statistics_unknown_options(ctl);
			break;
		default:
			log_warnx("wrong imsg type %d", imsg.hdr.type);
		}
		imsg_free(&imsg);
	}

	if (n == -1) {
		errstr = "imsg_get(3)";
		log_warn(errstr);
 fail:
		if (errstr == NULL)
			errstr = "probably wrong payload length";
		imsg_compose(&ctl->ibuf, IMSG_ERROR, 0, 0, -1, errstr,
		    strnlen(errstr, ERR_BUF_SIZE));
		if (imsg_flush(&ctl->ibuf))
			log_warn("imsg_flush error");
 finish:
		imsg_free(&imsg);
		control_finish(ctl);
	}
	else {
		imsg_compose(&ctl->ibuf, IMSG_DONE, 0, 0, -1, NULL, 0);
		if (imsg_flush(&ctl->ibuf)) {
			log_warn("imsg_flush IMSG_DONE");
			control_finish(ctl);
			return;
		}

		/* Wait for the next command. */
		if (event_add(&ctl->ev, NULL)) {
			log_warn("event_add(3)");
			control_finish(ctl);
			return;
		}
	}
	return;
}
