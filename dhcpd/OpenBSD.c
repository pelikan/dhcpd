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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <assert.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "dhcpd.h"
#include "bpf.h"
#include "interface.h"

/*
 * Privileged functions below.
 */

static int
bpf_register_receive(int sock)
{
	struct bpf_version v;
	struct bpf_program p;
	int flag = 1;

	if (ioctl(sock, BIOCVERSION, &v) == -1) {
		log_warn("ioctl(BIOCVERSION) on BPF");
		return (-1);
	}

	if (v.bv_major != BPF_MAJOR_VERSION || v.bv_minor < BPF_MINOR_VERSION)
		fatalx("Kernel BPF version is wrong - recompile dhcpd!");

	/* Get data out immediately instead of waiting on the buffer to fill. */
	if (ioctl(sock, BIOCIMMEDIATE, &flag) == -1) {
		log_warn("ioctl(BIOCIMMEDIATE) on BPF");
		return (-1);
	}

	/* Drop what you caught -- there are no other listeners. */
	if (ioctl(sock, BIOCSFILDROP, &flag) == -1) {
		log_warn("ioctl(BIOCSFILDROP) on BPF");
		return (-1);
	}

	/* Make the kernel fill in the source ethernet address. */
	flag = 0;
	if (ioctl(sock, BIOCSHDRCMPLT, &flag) == -1) {
		log_warn("ioctl(BIOCSHDRCMPLT) on BPF");
		return (-1);
	}

	/* Load both the receive and send BPFs into the kernel. */
	p.bf_len = sizeof(dhcp_bpf_rfilter) / sizeof(struct bpf_insn);
	p.bf_insns = dhcp_bpf_rfilter;
	if (ioctl(sock, BIOCSETF, &p) == -1) {
		log_warn("ioctl(BIOCSETF) on BPF");
		return (-1);
	}
	p.bf_len = sizeof(dhcp_bpf_wfilter) / sizeof(struct bpf_insn);
	p.bf_insns = dhcp_bpf_wfilter;
	if (ioctl(sock, BIOCSETWF, &p) == -1) {
		log_warn("ioctl(BIOCSETWF) on BPF");
		return (-1);
	}

	/* Lock the BPF file descriptor to prevent unpriv changes. */
	if (ioctl(sock, BIOCLOCK, &p) == -1) {
		log_warn("ioctl(BIOCLOCK) on BPF");
		return (-1);
	}
	return (sock);
}

int
bpf_socket_open(char *ifname)
{
	int		fd, i;
	char		bpf[sizeof "/dev/bpf9999"];
	struct ifreq	ifr;

	memset(&ifr, 0, sizeof ifr);
	if (strlcpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name) >=
	    sizeof ifr.ifr_name)
		fatalx("bpf ifreq: interface name too long");

	for (i = 0; i < 99; ++i) {
		snprintf(bpf, sizeof bpf, "/dev/bpf%d", i);
		if ((fd = open(bpf, O_RDWR, 0)) == -1) {
			if (errno == EBUSY)
				continue;
			else
				return (-1);
		}
		break;
	}

	if (ioctl(fd, BIOCSETIF, &ifr) == -1) {
		log_warn("ioctl(BIOCSETIF, %s) on BPF", ifname);
		close(fd);
		fd = -1;
	}

	if (bpf_register_receive(fd) == -1) {
		close(fd);
		fd = -1;
	}
	return (fd);
}

int
rtsock_init(void)
{
	unsigned rtfilter, async = 1;
	int s;

	if ((s = socket(PF_ROUTE, SOCK_RAW, PF_UNSPEC)) == -1) {
		log_warn("creating the routing socket (RAW/UNSPEC)");
		return (-1);
	}

	if (ioctl(s, FIONBIO, &async) == -1) {
		log_warn("ioctl FIONBIO rtsock");
		goto fail;
	}

	rtfilter = ROUTE_FILTER(RTM_NEWADDR) | ROUTE_FILTER(RTM_DELADDR) |
	    ROUTE_FILTER(RTM_IFANNOUNCE) | ROUTE_FILTER(RTM_IFINFO);
	if (setsockopt(s, PF_ROUTE, ROUTE_MSGFILTER,
	    &rtfilter, sizeof rtfilter) == -1) {
		log_warn("setsockopt ROUTE_MSGFILTER");
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

#define ROUNDUP(a)	\
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static void
ifa_get_addrs(struct ifa_msghdr *ia, struct sockaddr **rti_info)
{
	char *p = (char *)ia + ia->ifam_hdrlen;
	struct sockaddr *sa = (struct sockaddr *)p;;
	unsigned i;

	for (i = 0; i < RTAX_MAX; ++i) {
		if (ia->ifam_addrs & (1 << i)) {
			rti_info[i] = sa;
			p = (char *)sa + ROUNDUP(sa->sa_len);
			sa = (struct sockaddr *)p;
		}
		else
			rti_info[i] = NULL;
	}
}

#define READ_THE_REST(wholepkt)				\
	while (total != (wholepkt)) {			\
		rcvd = read(sock, buf + total,		\
		    (wholepkt) - total);		\
		if (rcvd == -1) {			\
			log_warn("read rtsock rest");	\
			return;				\
		}					\
		else if (rcvd == 0) {			\
			log_warn("rtsock closed");	\
			return;				\
		}					\
		total += rcvd;				\
	}

void
rtsock_dispatch(int sock, short ev, void *arg)
{
	union {
		struct rt_msghdr rt;
		struct if_msghdr i;
		struct ifa_msghdr ia;
		struct if_announcemsghdr ann;
	} *m;
	char buf[sizeof *m + RTAX_MAX * sizeof(struct sockaddr_storage)];
	struct sockaddr *rti_info[RTAX_MAX];
	struct sockaddr_in *sin;
	struct sockaddr_dl *sdl;
	u_int32_t ipv4 = 0;
	u_int8_t plen = 0;
	char ifname[IF_NAMESIZE + 1];
	int ifnamlen = 0;
	ssize_t rcvd, total;
	struct network_interface *ni;

	assert(ev == EV_READ);
	assert(arg == NULL);

	if ((rcvd = read(sock, buf, sizeof *m)) == -1) {
		log_warn("read rtsock");
		return;
	}
	if (rcvd == 0) {
		log_warnx("routing socket closed");
		return;
	}
	total = rcvd;
	m = (void *) buf;
	switch (m->rt.rtm_type) {
	case (RTM_NEWADDR):
		READ_THE_REST(m->ia.ifam_msglen);
		ifa_get_addrs(&m->ia, rti_info);

		if (rti_info[RTAX_NETMASK]) {
			sin = (struct sockaddr_in *)rti_info[RTAX_NETMASK];
			plen = mask2plen32(ntohl(sin->sin_addr.s_addr));
		}

		if (rti_info[RTAX_IFP]) {
			sdl = (struct sockaddr_dl *)rti_info[RTAX_IFP];
			ifnamlen = MIN(sdl->sdl_nlen, IF_NAMESIZE);
			memcpy(ifname, sdl->sdl_data, ifnamlen);
			ifname[ifnamlen] = '\0';
			if ((ni = interface_by_name(&ifs_used, ifname)) == NULL)
				ni = interface_by_name(&ifs_nuse, ifname);
		}
		else
			ni = NULL;

		if (rti_info[RTAX_IFA]) {
			sin = (struct sockaddr_in *)rti_info[RTAX_IFA];
			ipv4 = sin->sin_addr.s_addr;
		}
		if (ni && ipv4 && plen)
			ipv4_addr_arrived(ni, ipv4, plen);
		else
			log_warnx("RTM_NEWADDR wrong: ni %p addr 0x%x plen %d",
			    ni, ipv4, plen);
		break;

	case (RTM_DELADDR):
		READ_THE_REST(m->ia.ifam_msglen);
		ifa_get_addrs(&m->ia, rti_info);

		if (rti_info[RTAX_IFA]) {
			sin = (struct sockaddr_in *)rti_info[RTAX_IFA];
			ipv4 = sin->sin_addr.s_addr;
		}
		/*
		 * Very common case: one subnet, carpdev /24, carp /32.
		 * Absolutely need to know which one is going away.
		 */
		if (rti_info[RTAX_NETMASK]) {
			sin = (struct sockaddr_in *)rti_info[RTAX_NETMASK];
			plen = mask2plen32(ntohl(sin->sin_addr.s_addr));
		}
		if (ipv4 && plen)
			ipv4_addr_departed(ipv4, plen);
		else
			log_warnx("RTM_DELADDR wrong: addr 0x%x plen %d",
			    ipv4, plen);
		break;

	case (RTM_IFINFO):
		log_warnx("RTM_IFINFO: iface %u: status %s", m->i.ifm_index,
		    (m->i.ifm_flags & IFF_UP) ? "UP" : "DOWN");
		break;

	case (RTM_IFANNOUNCE):
		switch (m->ann.ifan_what) {
		case (IFAN_ARRIVAL):
			interface_arrived(m->ann.ifan_index, m->ann.ifan_name);
			break;
		case (IFAN_DEPARTURE):
			interface_departed(m->ann.ifan_name);
			break;
		default:
			log_warnx("ANNOUNCE index %u what %u name %s",
			    m->ann.ifan_index, m->ann.ifan_what,
			    m->ann.ifan_name);
			break;
		}
		break;

	default:
		log_warnx("rcvd routing msg type %d", m->rt.rtm_type);
		break;
	}
}
#undef READ_THE_REST

int
interfaces_discover(void)
{
	struct ifaddrs *ifap, *p;
	unsigned idx;
	u_int8_t plen;
	struct sockaddr_in *sin;
	struct sockaddr_in *m;
	struct network_interface *nif = NULL;
	int count = 0;

	if (getifaddrs(&ifap) < 0) {
		log_warn("getifaddrs");
		return (-1);
	}
	for (p = ifap; p != NULL; p = p->ifa_next) {
                if ((p->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)))
			continue;

		sin = (struct sockaddr_in *) p->ifa_addr;
		m = (struct sockaddr_in *) p->ifa_netmask;

		/* This function is only called at the start.  No duplicates. */
		idx = if_nametoindex(p->ifa_name);
		if (nif == NULL || strcmp(nif->name, p->ifa_name)) {
			nif = interface_arrived(idx, p->ifa_name);
			if (nif == NULL)
				goto fail;
			++count;
		}

		switch (p->ifa_addr->sa_family) {
		case (AF_INET):
			plen = mask2plen32(ntohl(m->sin_addr.s_addr));
			if (ipv4_addr_arrived(nif, sin->sin_addr.s_addr,
			    plen) == NULL)
				goto fail;
			break;
		}
	}

	freeifaddrs(ifap);
	return (count);

 fail:
	freeifaddrs(ifap);
	return (-1);
}

void
bpf_event(int fd, short ev, void *arg)
{
	struct network_interface	*ni = arg;
	struct bpf_hdr			*hdr;
	u_int8_t			*data;
	ssize_t				 n, off, len;

	(void) ev;

	if ((n = read(fd, ni->rbuf, ni->size)) == -1) {
		log_warn("BPF read(2)");
		return;
	}
	log_debug_io("BPF read %zd bytes", n);

	off = 0;
	do {
		hdr = (struct bpf_hdr *) (ni->rbuf + off);
		log_debug_io("BPF header caplen %u datalen %u hdrlen %u",
		    hdr->bh_caplen, hdr->bh_datalen, hdr->bh_hdrlen);

		data = ni->rbuf + hdr->bh_hdrlen;
		len = hdr->bh_datalen;

		bpf_input(ni, data, len);

		off += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
	} while (n - off > 0);
}

size_t
bpf_required_size(int fd)
{
	size_t size;

	if (ioctl(fd, BIOCGBLEN, &size) == -1 || size == 0) {
		close(fd);
		log_warn("BIOCGBLEN in unpriv doesnt work.");
		return 0;
	}

	return (size);
}
