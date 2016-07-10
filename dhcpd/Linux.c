/*
 * Copyright (c) 2012, 2016 Martin Pelikan <pelikan@storkhole.cz>
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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <pcap/bpf.h>
#include <assert.h>
#include <event.h>
#include <string.h>
#include <unistd.h>

#include "dhcpd.h"
#include "bpf.h"
#include "interface.h"

#define	RTATTR_START(x, type)	\
	((struct rtattr *)( ((char *)(x)) + NLMSG_ALIGN(sizeof(struct type)) ))
#define	RTATTR_FOREACH(p, type, start, len)				\
	for ((p) = RTATTR_START(start, type); RTA_OK((p), (len));	\
	    (p) = RTA_NEXT((p), (len)))
#define	NLMSG_FOREACH(p, start, len)				\
	for ((p) = (struct nlmsghdr *)(start); NLMSG_OK((p), (len));	\
	    (p) = NLMSG_NEXT((p), (len)))

/*
 * Privileged functions below.
 */

static int
bpf_register_receive(int sock)
{
	struct sock_fprog bpf;
	int lock = 1;

	/* XXX Linux apparently doesn't offer separate read/write filters. */
	memset(&bpf, 0, sizeof bpf);
	bpf.len = sizeof dhcp_bpf_rfilter / sizeof *dhcp_bpf_rfilter;
	bpf.filter = dhcp_bpf_rfilter;

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof bpf) == -1) {
		log_warn("setsockopt SO_ATTACH_FILTER");
		return (-1);
	}
	if (setsockopt(sock, SOL_SOCKET, SO_LOCK_FILTER, &lock, sizeof lock) == -1) {
		log_warn("setsockopt SO_LOCK_FILTER");
		return (-1);
	}
	if (setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER, &bpf, sizeof bpf) != -1) {
		log_warn("setsockopt SO_DETACH_FILTER should have failed");
		return (-1);
	}
	return (sock);
}

int
bpf_socket_open(char *ifname)
{
	struct sockaddr_ll sll;
	struct ifreq ifr;
	int fd;

	memset(&ifr, 0, sizeof ifr);
	strncpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name);

	memset(&sll, 0, sizeof sll);
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);

	if ((fd = socket(AF_PACKET, SOCK_RAW, sll.sll_protocol)) == -1) {
		log_warn("socket");
		return (-1);
	}
	if (ioctl(fd, SIOCGIFINDEX, &ifr, sizeof ifr) == -1) {
		log_warn("ioctl SIOCGIFINDEX");
		goto fail;
	}

	sll.sll_ifindex = ifr.ifr_ifindex;

	if (bind(fd, (struct sockaddr *)&sll, sizeof sll) == -1) {
		log_warn("bind");
		goto fail;
	}

	if (bpf_register_receive(fd) == -1) {
		close(fd);
		fd = -1;
	}

	return (fd);
 fail:
	close(fd);
	return (-1);
}

int
rtsock_init(void)
{
	struct sockaddr_nl snl;
	unsigned long async = 1;
	int s;

	if ((s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) == -1) {
		log_warn("socket(AF_NETLINK, NETLINK_ROUTE)");
		return (-1);
	}

	memset(&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;
	snl.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;

	if (bind(s, (struct sockaddr *)&snl, sizeof snl) == -1) {
		log_warn("bind RTMGRP_* netlink");
		goto fail;
	}

	if (ioctl(s, FIONBIO, &async) == -1) {
		log_warn("ioctl FIONBIO netlink");
		goto fail;
	}
	return (s);
 fail:
	close(s);
	return (-1);
}

/*
 * Unprivileged functions below.
 */

/* Do not trust the kernel to NUL-terminate the string. */
static void
extract_ifname(char *ifname, struct rtattr *p)
{
	int ifnamelen = MIN(p->rta_len - sizeof *p, IF_NAMESIZE);
	memcpy(ifname, p + 1, ifnamelen);
	ifname[ifnamelen] = '\0';
}

static void
rtnl_add_link(struct nlmsghdr *hdr, struct ifinfomsg *ifi, ssize_t len)
{
	ssize_t remain = len - NLMSG_LENGTH(sizeof *ifi);
	char ifname[IF_NAMESIZE + 1];
	struct rtattr *p;

	log_debug("RTM_NEWLINK ifi_index %d, got %zd want %u\n",
	    ifi->ifi_index, len, hdr->nlmsg_len);

	RTATTR_FOREACH(p, ifinfomsg, ifi, remain) {
		switch (p->rta_type) {
		case (IFLA_IFNAME):
			extract_ifname(ifname, p);
			interface_arrived(ifi->ifi_index, ifname);
			return;
		}
	}
	log_warnx("RTM_NEWLINK incomplete");
}

static void
rtnl_del_link(struct nlmsghdr *hdr, struct ifinfomsg *ifi, ssize_t len)
{
	ssize_t remain = len - NLMSG_LENGTH(sizeof *ifi);
	char ifname[IF_NAMESIZE + 1];
	struct rtattr *p;

	log_debug("RTM_DELLINK ifi_index %d, got %zd want %u\n",
	    ifi->ifi_index, len, hdr->nlmsg_len);

	RTATTR_FOREACH(p, ifinfomsg, ifi, remain) {
		switch (p->rta_type) {
		case (IFLA_IFNAME):
			extract_ifname(ifname, p);
			interface_departed(ifname);
			return;
		}
	}
	log_warnx("RTM_DELLINK incomplete");
}

static void
rtnl_add_addr(struct nlmsghdr *hdr, struct ifaddrmsg *ifa, ssize_t len)
{
	ssize_t remain = len - NLMSG_LENGTH(sizeof *ifa);
	struct network_interface *ni;
	char ifname[IF_NAMESIZE + 1];
	int fields = 0;
	u_int32_t ipv4 = 0;
	struct rtattr *p;

	if (ifa->ifa_family != AF_INET)
		return;

	log_debug("RTM_NEWADDR ifa_index %d, ifa_plen %d, got %zd want %u\n",
	    ifa->ifa_index, ifa->ifa_prefixlen, len, hdr->nlmsg_len);

	RTATTR_FOREACH(p, ifaddrmsg, ifa, remain) {
		switch (p->rta_type) {
		/* NOTE: IFA_ADDRESS is a prefix address. */
		case (IFA_LOCAL):
			if (p->rta_len != sizeof *p + sizeof ipv4) {
				log_warnx("RTM_NEWADDR bad IFA_LOCAL len %d",
				    p->rta_len);
				return;
			}
			memcpy(&ipv4, p + 1, sizeof ipv4);
			++fields;
			break;
		case (IFA_LABEL):
			extract_ifname(ifname, p);
			++fields;
			break;
		}
	}

	if (fields != 2) {
		log_warnx("RTM_NEWADDR incomplete; only %d fields", fields);
		return;
	}

	if ((ni = interface_by_name(&ifs_used, ifname)) == NULL)
		ni = interface_by_name(&ifs_nuse, ifname);

	if (ni && ipv4 && ifa->ifa_prefixlen)
		ipv4_addr_arrived(ni, ipv4, ifa->ifa_prefixlen);
	else
		log_warnx("RTM_NEWADDR wrong: ni %p addr 0x%x prefixlen %d",
		    ni, ipv4, ifa->ifa_prefixlen);
}

static void
rtnl_del_addr(struct nlmsghdr *hdr, struct ifaddrmsg *ifa, ssize_t len)
{
	ssize_t remain = len - NLMSG_LENGTH(sizeof *ifa);
	u_int32_t ipv4 = 0;
	struct rtattr *p;

	if (ifa->ifa_family != AF_INET)
		return;

	log_debug("RTM_DELADDR ifa_index %d, ifa_plen %d, got %zd want %u\n",
	    ifa->ifa_index, ifa->ifa_prefixlen, len, hdr->nlmsg_len);

	RTATTR_FOREACH(p, ifaddrmsg, ifa, remain) {
		/* NOTE: IFA_ADDRESS is a prefix address. */
		if (p->rta_type != IFA_LOCAL)
			continue;

		if (p->rta_len != sizeof *p + sizeof ipv4) {
			log_warnx("RTM_DELADDR bad IFA_LOCAL len %d",
			    p->rta_len);
			return;
		}
		memcpy(&ipv4, p + 1, sizeof ipv4);
		break;
	}

	if (ipv4 && ifa->ifa_prefixlen)
		ipv4_addr_departed(ipv4, ifa->ifa_prefixlen);
	else
		log_warnx("RTM_DELADDR wrong: addr 0x%x prefixlen %d",
		    ipv4, ifa->ifa_prefixlen);
}

void
routing_socket_parse(struct nlmsghdr *hdr, ssize_t len)
{
	switch (hdr->nlmsg_type) {
	case (RTM_NEWLINK):
		rtnl_add_link(hdr, NLMSG_DATA(hdr), len);
		break;
	case (RTM_DELLINK):
		rtnl_del_link(hdr, NLMSG_DATA(hdr), len);
		break;
	case (RTM_NEWADDR):
		rtnl_add_addr(hdr, NLMSG_DATA(hdr), len);
		break;
	case (RTM_DELADDR):
		rtnl_del_addr(hdr, NLMSG_DATA(hdr), len);
		break;
	default:
		log_warnx("%s: nlmsg_type %u\n", __func__, hdr->nlmsg_type);
		break;
	}
}

/*
 * Netlink is a typical example of Linux taking a perfectly sane interface
 * (PF_ROUTE) and then making a complete mess where ANYTHING can happen.
 *
 * When we do a short read, the whole message is GONE.  We can't use the safe
 * approach of asking for the length first by reading the header, because the
 * subsequent read(2) will contain a different header.
 */
void
rtsock_dispatch(int sock, short ev, void *arg)
{
	struct nlmsghdr *n;
	u_int8_t buf[4096];
	ssize_t rcvd;

	assert(ev == EV_READ);
	assert(arg == NULL);

	if ((rcvd = read(sock, buf, sizeof buf)) == -1) {
		log_warn("read netlink");
		return;
	}
	if (rcvd == 0) {
		log_warnx("netlink socket closed");
		return;
	}

	NLMSG_FOREACH(n, buf, rcvd) {
		routing_socket_parse(n, rcvd);
	}
}

void
bpf_event(int fd, short ev, void *arg)
{
	struct network_interface *ni = arg;
	ssize_t rcvd;

	assert(ev == EV_READ);
	assert(arg != NULL);

	if ((rcvd = read(fd, ni->rbuf, ni->size)) == -1) {
		log_warn("BPF read(2)");
		return;
	}

	log_debug_io("BPF read %zd bytes", rcvd);
	bpf_input(ni, ni->rbuf, rcvd);
}

size_t
bpf_required_size(int fd)
{
	/* XXX figure out if there's an ioctl for this. */
	(void) fd;
	return 2048;
}
