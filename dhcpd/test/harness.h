/* Test harness to support network-independent testing and fuzzing. */
#pragma once

u_int64_t stats[STATS__MAXIMUM];
struct group default_group;
struct shared_network default_shared_network;

struct network_interface fake_interface;
struct network_address fake_address;

void
event_set(struct event *x, int y, short z, void (*f)(int, short, void *), void *p)
{
	(void)x; (void)y; (void)z; (void)f; (void)p;
}

int
event_pending(const struct event *x, short y, struct timeval *tv)
{
	(void)x; (void)y; (void)tv;
	return 0;
}

int
event_add(struct event *x, const struct timeval *tv)
{
	(void) x; (void)tv;
	return 0;
}

int
event_del(struct event *x)
{
	(void) x;
	return 0;
}

int
unprivileged_ask_for_bpf(const char *s)
{
	(void)s;
	return 0;
}

int
unprivileged_ask_for_udp(u_int32_t u)
{
	(void)u;
	return 0;
}

size_t
bpf_required_size(int fd)
{
	(void)fd;
	return 2048;
}

/* XXX maybe merge this with dhcpd.c somehow */
static void
set_defaults(void)
{
	default_group.refcnt = 1;
	strlcpy(default_group.name, "default", sizeof "default");
	RB_INSERT(group_tree, &groups, &default_group);

	default_shared_network.name = "default";
	default_shared_network.group = group_use(&default_group);
	RB_INIT(&default_shared_network.hosts);
	RB_INSERT(shared_network_tree, &shared_networks, &default_shared_network);

	strlcpy(fake_interface.name, "fake0", sizeof fake_interface.name);
	fake_interface.fd = -1;
	RB_INSERT(network_interface_tree, &ifs_used, &fake_interface);

	fake_address.ni = &fake_interface;
	fake_address.ipv4.s_addr = htonl(0xC0A80101);
	fake_address.prefixlen = 16;
	fake_address.shared = &default_shared_network;
	RB_INSERT(ipv4_address_tree, &ifa_used, &fake_address);

	char *errstr;
	struct ctl_subnet subnet;
	subnet.network.s_addr = htonl(0xC0A80100);
	subnet.prefixlen = 16;
	strlcpy(subnet.shared, "default", sizeof subnet.shared);
	strlcpy(subnet.group, "default", sizeof subnet.group);
	errstr = subnet_add(&subnet);
	log_info("subnet_add: %s", errstr);

	struct ctl_subnet_settings settings;
	memset(&settings, 0, sizeof settings);
	strlcpy(settings.shared, "default", sizeof settings.shared);
	settings.network.s_addr = htonl(0xC0A80100);
	settings.prefixlen = 16;
	settings.range_lo.s_addr = htonl(0xC0A801AA);
	settings.range_hi.s_addr = htonl(0xC0A801BB);
	settings.flags |= SUBNET_WANT_RANGE;
	errstr = subnet_set(&settings);
	log_info("subnet_set: %s", errstr);
}
