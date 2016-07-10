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

#include <sys/wait.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dhcpd.h"

enum {
	CONTROL_SOCKET,
	ROUTING_SOCKET,
	PRIVSEP_SOCKET,
	LEASE_SYNCER_SOCKET,
	__SOCKETS_ALWAYS_PRESENT__
};

#define __SIGNAL_HANDLERS__	5
struct event events[__SOCKETS_ALWAYS_PRESENT__], sigevents[__SIGNAL_HANDLERS__];

int control_sock = -1, kernel_rtsock = -1, syncer_sock = -1, privsep_sock = -1;
pid_t privileged_pid;
int privileged_exit_code;
u_int64_t stats[STATS__MAXIMUM];

struct shared_network	default_shared_network;
struct group		default_group;


static void
unprivileged_signal_handler(int sig, short ev, void *arg)
{
	(void) ev; (void) arg;

	switch (sig) {
	case SIGPIPE:
		break;
	case SIGCHLD:
		if (waitpid(privileged_pid, &privileged_exit_code, WNOHANG) ==
		    privileged_pid) {
			if (privileged_exit_code)
				log_warnx("privileged child died with %d",
				    privileged_exit_code);
			event_loopbreak();
		}
		break;
	case SIGHUP:
		break;
	default:
		event_loopbreak();
		break;
	}
}

static void
drop_privileges(struct passwd *pw)
{
	int pair[2] = { -1, -1 };

	if (geteuid())
		fatalx("in order to drop privileges you need to have them!");

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pair) == -1)
		fatal("socketpair(2)");

	switch ((privileged_pid = fork())) {
	case -1:
		fatal("forking unprivileged process");
		/* NOTREACHED */
	case 0:
		privsep_init(pair[0], pair[1]);
		setproctitle("[priv]");

		exit(privileged_main());
		/* NOTREACHED */
	}
	privsep_init(pair[1], pair[0]);
	setproctitle("dhcp engine");

	if (chroot(CHROOT_PATH) == -1)
		fatal("chroot(" CHROOT_PATH ") failed");
	if (chdir("/") == -1)
		fatal("chdir inside chroot failed");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges to " UNPRIVILEGED_USER);
}

static void
set_defaults(void)
{
	u_int8_t *buf;
	u_int32_t t = htonl(DEFAULT_LEASE_TIME);

	/* Initialize some default timers essential for many clients. */
	if ((buf = malloc(1 + sizeof t)) == NULL)
		goto nomem;

	buf[0] = sizeof t;
	memcpy(buf + 1, &t, sizeof t);
	default_group.options[DHCP_OPT_ADDR_LEASETIME] = buf;

	/* Initialize the default group and shared_network. */
	default_group.refcnt = 1;
	strlcpy(default_group.name, "default", sizeof "default");
	RB_INSERT(group_tree, &groups, &default_group);

	default_shared_network.name = "default";
	default_shared_network.group = group_use(&default_group);
	RB_INIT(&default_shared_network.hosts);
	RB_INSERT(shared_network_tree, &shared_networks,
	    &default_shared_network);

	return;
 nomem:
	fatalx("out of memory really quite soon");
}

static int
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-d] [-s path-to-socket]\n", __progname);
	return (EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	struct passwd *pw;
	char *ctlpath = NULL;
	int ch, debug = 0;

	while ((ch = getopt(argc, argv, "ds:")) != -1) {
		switch (ch) {
		case 'd':
			++debug;
			break;
		case 's':
			ctlpath = optarg;
			break;
		default:
			return usage();
		}
	}

	argc -= optind;
	argv += optind;

	if ((pw = getpwnam(UNPRIVILEGED_USER)) == NULL)
		err(1, "there isn't any user called " UNPRIVILEGED_USER);

	if (control_sock == -1)
		control_sock = control_init(ctlpath, pw->pw_uid, pw->pw_gid);
	if (control_sock == -1)
		errx(1, "there isn't any control socket.");

	if ((kernel_rtsock = rtsock_init()) == -1)
		errx(1, "there isn't any routing socket.");

	log_init(debug);
	log_info("starting");

	if (!debug && daemon(1, 0) != 0)
		fatal("daemon(3)");

	drop_privileges(pw);
	set_defaults();

	if (event_init() == NULL)
		fatal("event_init");

	if (interfaces_discover() == -1)
		fatal("discovering interfaces");

	signal_set(&sigevents[0], SIGHUP, unprivileged_signal_handler, NULL);
	signal_set(&sigevents[1], SIGINT, unprivileged_signal_handler, NULL);
	signal_set(&sigevents[2], SIGTERM, unprivileged_signal_handler, NULL);
	signal_set(&sigevents[3], SIGCHLD, unprivileged_signal_handler, NULL);
	signal_set(&sigevents[4], SIGPIPE, unprivileged_signal_handler, NULL);

	for (int i = 0; i < __SIGNAL_HANDLERS__; ++i)
		if (signal_add(&sigevents[i], NULL))
			fatal("signal_add");

	event_set(&events[CONTROL_SOCKET], control_sock, EV_READ | EV_PERSIST,
	    control_accept, NULL);
	event_set(&events[ROUTING_SOCKET], kernel_rtsock, EV_READ | EV_PERSIST,
	    rtsock_dispatch, NULL);
	event_set(&events[PRIVSEP_SOCKET], privsep_sock, EV_READ | EV_PERSIST,
	    unprivileged_dispatch, NULL);

	//for (int i = 0; i < __SOCKETS_ALWAYS_PRESENT__; ++i)
	for (int i = 0; i <= PRIVSEP_SOCKET; ++i)
		if (event_add(events + i, NULL))
			fatal("event_add");

	stats[STATS_DAEMON_STARTED] = time(NULL);
	event_dispatch();

	for (int i = 0; i <= PRIVSEP_SOCKET; ++i)
		event_del(&events[i]);

	for (int i = 0; i < __SIGNAL_HANDLERS__; ++i)
		signal_del(&sigevents[i]);

	close(control_sock);
	unsatisfied_purge();
	interfaces_destroy();
	log_info("exitting %s", privileged_exit_code ? "badly" : "gracefully");
	return (privileged_exit_code);
}
