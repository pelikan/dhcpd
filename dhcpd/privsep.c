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
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dhcpd.h"

volatile sig_atomic_t	run = 1, want_reload = 1;
extern int		privsep_sock;
struct imsgbuf		imsgbuf;
char * const		reload_args[] = { "dhcpctl", "reload", NULL };
pid_t			reload_finished;
int			reload_status;

void
privsep_init(int tight, int loose)
{
	close(loose);
	privsep_sock = tight;
	imsg_init(&imsgbuf, privsep_sock);
}

static int
udp_socket_open(struct in_addr *a)
{
	int fd;
	struct sockaddr_in sin = {
	    sizeof(sin), AF_INET, htons(BOOTP_SERVER_PORT), *a, {0}
	};

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return (-1);

	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)) == -1)
		goto fail;

	return (fd);

 fail:
	close(fd);
	return (-1);
}

static void
privileged_reload(void)
{
	pid_t pid;

	switch ((pid = fork())) {
	case (-1):
		log_warn("priv: fork(2) failed");
		break;
	case (0):
		switch (execve(PATH_DHCPCTL, reload_args, NULL)) {
		case (-1):
			log_warn("priv: execve(2) failed");
			break;
		}
		exit(1);
	}
	log_info("config-reloading PID %u started", pid);
	want_reload = 0;
}

static void
privileged_reload_finished(void)
{
	if (reload_status)
		log_info("config-reloading PID %u finished with %d",
		    reload_finished, reload_status);
	reload_finished = 0;
}

static void
privileged_signal_handler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		run = 0;
		break;
	case SIGCHLD:
		reload_finished = waitpid(WAIT_ANY, &reload_status, WNOHANG);
		break;
	case SIGHUP:
		want_reload = 1;
		break;
	}
}

int
privileged_main(void)
{
	int			fd, p = 0;
	ssize_t			n = -1;
	struct imsg		imsg;
	struct pollfd		pfd;
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = privileged_signal_handler;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);

	pfd.fd = privsep_sock;
	pfd.events = POLLIN;

	/* Serve our unprivileged parent's requests. */
	while (run) {
		if (want_reload)
			privileged_reload();
		if (reload_finished)
			privileged_reload_finished();

		switch (p = poll(&pfd, 1, POLL_TIMEOUT)) {
		case -1:
			if (errno != EINTR)
				fatal("priv: poll");
		case 0:
			continue;
		}

		if (pfd.revents & (POLLHUP | POLLERR))
			fatalx("priv: pfd.revents with HUP or ERR");
		if ((n = imsg_read(&imsgbuf)) == -1)
			fatal("priv: imsg_read(3)");

		while ((n = imsg_get(&imsgbuf, &imsg)) > 0) {
			size_t pld_len = imsg.hdr.len - IMSG_HEADER_SIZE;

			switch (imsg.hdr.type) {
			case IMSG_BPF:
				if (pld_len != IF_NAMESIZE)
					goto fail;

				if ((fd = bpf_socket_open(imsg.data)) == -1)
					goto fail;

				imsg_compose(&imsgbuf, IMSG_BPF, 0, 0, fd,
				    imsg.data, pld_len);
				break;
			case IMSG_UDP:
				if (pld_len != sizeof(struct in_addr))
					goto fail;

				if ((fd = udp_socket_open(imsg.data)) == -1)
					goto fail;

				imsg_compose(&imsgbuf, IMSG_UDP, 0, 0, fd,
				    imsg.data, pld_len);
				break;
			default:
				log_warnx("priv: imsg type %d", imsg.hdr.type);
			fail:
				imsg_compose(&imsgbuf, IMSG_ERROR, 0, 0, -1,
				    NULL, 0);
				break;
			}

			/* Send the reply back to the unprivileged parent. */
			if (imsg_flush(&imsgbuf) == -1)
				log_warn("priv: imsg_flush");
			imsg_free(&imsg);
		}
	}

	imsg_clear(&imsgbuf);
	log_info("priv: exitting\n");
	return (run ? EXIT_FAILURE : EXIT_SUCCESS);
}

int
unprivileged_ask_for_bpf(const char *ifname)
{
	char buf[IF_NAMESIZE];

	strlcpy(buf, ifname, IF_NAMESIZE);
	imsg_compose(&imsgbuf, IMSG_BPF, 0, 0, -1, buf, sizeof(buf));
	return (imsg_flush(&imsgbuf) == -1);
}

int
unprivileged_ask_for_udp(u_int32_t listenaddr)
{
	struct in_addr buf;

	buf.s_addr = listenaddr;
	imsg_compose(&imsgbuf, IMSG_UDP, 0, 0, -1, &buf, sizeof(buf));
	return (imsg_flush(&imsgbuf) == -1);
}

void
unprivileged_dispatch(int sock, short ev, void *arg)
{
	ssize_t		n;
	struct imsg	imsg;

	assert(sock == imsgbuf.fd);
	assert(ev == EV_READ);
	assert(arg == NULL);

	if ((n = imsg_read(&imsgbuf)) == -1) {
		log_warn("%s: imsg_read(3)", __func__);
		return;
	}

	while ((n = imsg_get(&imsgbuf, &imsg)) > 0) {
		size_t pld_len = imsg.hdr.len - IMSG_HEADER_SIZE;

		switch (imsg.hdr.type) {
		case IMSG_BPF:
			if (imsg.fd == -1 || pld_len != IF_NAMESIZE)
				goto fail;

			interface_assign_bpf(imsg.data, imsg.fd);
			break;
		case IMSG_UDP:
			if (imsg.fd == -1 || pld_len != sizeof(struct in_addr))
				goto fail;

			ipv4_addr_assign_udp(imsg.data, imsg.fd);
			break;

		case IMSG_ERROR:
			log_warnx("unpriv: imsg error was sent");
			break;
		default:
			log_warnx("unpriv: imsg type %d", imsg.hdr.type);
			break;
		}

 fail:
		imsg_free(&imsg);
	}
}

