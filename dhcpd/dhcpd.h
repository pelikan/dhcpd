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

#pragma once
#include <sys/queue.h>
#include <sys/tree.h>
#include <netinet/in.h>
#include <netinet/ip_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>

#include "control.h"

#define	UNPRIVILEGED_USER	"_dhcp"
#define	CHROOT_PATH	"/var/empty"
#define	PATH_CTLSOCK	"/var/run/dhcpd.sock"
#define	PATH_DHCPCTL	"/usr/sbin/dhcpctl"
#define	POLL_TIMEOUT	(120 * 1000)
#define	ERR_BUF_SIZE	(256)
#define	MTU		(1518)
#define	DEFAULT_LEASE_TIME	86400
#define	OFFER_LEASE_TIME	30
#define	UNSATISFIED_EXPIRY	120

#ifndef	MIN
#define	MIN(a,b)	(((a) < (b)) ? (a) : (b))
#endif

struct request;
struct reply;


/*
 * Groups of DHCP settings.
 * A bunch of options (or the extra stuff in the BOOTP header) is prepared by
 * the controller and stored as "1 byte length + n bytes data" of malloc(3)'d
 * memory in this structure.  Various pieces can then link to it, meaning
 * they wish to respect the settings in it.  This means the operation is all
 * memcpy(3) of valid data and the parsing has been done by the controller.
 *
 * Groups can be named, like "group accountants {}", the controller needs
 * to ensure that if they appear on multiple places, the settings won't
 * collide with each other, to avoid confusion.
 *
 * Groups can obviously be nested.  The order of searching for settings to
 * send is like this; the earlier settings obviously win:
 *
 *	(struct host)->group
 *	that (struct group)->group (until the deepest one has NULL)
 *	(struct subnet)->group
 *	that (struct group)->group (until the deepest one has NULL)
 *	(struct shared_network)->group
 *	that (struct group)->group (until the deepest one has NULL)
 *	    The "default" group which can't be deleted and
 *	    contains "failsafe" parameters as last resort.
 *
 * which may look like this in the config file
 *
 * DEFAULT settings are a group as well
 * group A { group B {
 * 	shared_network { group C { group D {
 *	 	subnet { group E { group F {
 *	 		host {
 *			these settings are a group as well
 *			}
 *		}}
 *		these settings are a group as well
 *		}
 *	}}
 *	these settings are a group as well
 *	}
 * }}
 *
 * If you, for example, link group B to a host somewhere, rules from group A
 * apply as well, due to nesting.  Usecases include "group employees { group
 * cleaners { group dirty_ones { }}}", an 'is-a-subset-of' relationship.
 */
struct group {
	RB_ENTRY(group)	 allgroups;
	char		 name[NAME_SIZE];
	int		 refcnt;
	struct group	*next;

	u_int32_t	 flags;
	char		*filename;
	char		*sname;
	struct in_addr	 next_server;

	u_int8_t	*options[256];
};

/* First byte of flags reserved for struct ctl_group_settings in control.h */
#define	GROUP_DEFAULT		0x0100
#define	GROUP_MODIFIED		0x0200

char *	group_create(struct ctl_group *);
int	group_free(struct group *);
char *	group_set(struct ctl_group_settings *, size_t);
char *	group_unset(struct ctl_group_settings *, size_t);
int	group_cmp(struct group *, struct group *);
void	group_copyout_chain(struct reply *, struct group *);
struct group *	group_find(char *);
struct group *	group_use(struct group *);
extern struct group default_group;
extern RB_HEAD(group_tree, group) groups;
RB_PROTOTYPE(group_tree, group, allgroups, group_cmp)


/*
 * Relay IPv4 address -> shared_network mappings.
 */
struct relay {
	RB_ENTRY(relay)		 relays;
	struct in_addr		 relay;
	struct shared_network	*shared;
};
int	relay_cmp(struct relay *, struct relay *);
char *	relay_on(struct ctl_relay *);
char *	relay_off(struct ctl_relay *);
char *	relays_dump(struct ctl_relay **, ssize_t *, ssize_t *, struct in_addr);
RB_HEAD(relay_tree, relay);
RB_PROTOTYPE(relay_tree, relay, relays, relay_cmp)


/*
 * Hosts.
 */
struct host {
	RB_ENTRY(host)		 in_subnet;
	RB_ENTRY(host)		 in_shared;

	struct in_addr		 address;
	struct ether_addr	 mac;
	struct subnet		*subnet;
	struct lease		*lease;
	struct group		*group;
	char			*name;
};

char *	host_add(struct ctl_host *);
char *	host_delete(struct ctl_host *);
int	host_ipv4_cmp(struct host *, struct host *);
int	host_mac_cmp(struct host *, struct host *);
RB_HEAD(host_ipv4_tree, host);
RB_HEAD(host_mac_tree, host);
RB_PROTOTYPE(host_ipv4_tree, host, in_subnet, host_ipv4_cmp)
RB_PROTOTYPE(host_mac_tree, host, in_shared, host_mac_cmp)


/*
 * Leases.
 * The host pointer is ONLY to delete host->lease when the lease dies.
 * We need to keep the group even after a static host entry is gone,
 * to maintain consistent network configuration during our lifetime.
 */
enum lease_state {
	OFFERED,
	ACKED,
	DECLINED,
};
struct lease {
	RB_ENTRY(lease)		 leases_by_expiry;
	RB_ENTRY(lease)		 leases_by_mac;
	struct timeval		 allocated;
	struct timeval		 expires;
	struct in_addr		 address;
	struct ether_addr	 mac;
	struct subnet		*subnet;
	struct group		*group;
	struct host		*host;
	enum lease_state	 state;

	char			 last_hostname[64];
	char			 last_vendor_classid[64];
};
int	lease_expiry_cmp(struct lease *, struct lease *);
int	lease_mac_cmp(struct lease *, struct lease *);
void	lease_free(struct lease *);
void	lease_purger_plan(int);
char *	lease_kill(struct ctl_lease *);
ssize_t	leases_dump(struct ctl_lease **, ssize_t *);
struct lease *	lease_new(struct subnet *, struct in_addr, struct ether_addr *, struct group *, int);
struct lease *	lease_new_dynamic(struct request *, int);
struct lease *	lease_previous_dynamic(struct request *, struct in_addr);
struct lease *	lease_find_mac(struct request *);
struct lease *	lease_decline(struct request *, struct lease *);
extern RB_HEAD(lease_expiry_tree, lease) leases_by_expiration;
RB_HEAD(lease_mac_tree, lease);
RB_PROTOTYPE(lease_expiry_tree, lease, leases, lease_expiry_cmp)
RB_PROTOTYPE(lease_mac_tree, lease, leases, lease_mac_cmp)


/*
 * Subnets.
 */
struct subnet {
	RB_ENTRY(subnet)	 subnets;
	struct in_addr		 network;
	u_int8_t	 	 prefixlen;
	int			 refcnt;
	struct shared_network	*shared;
	struct group		*group;

	struct host_ipv4_tree	 hosts;
	struct range		*range;
};

char *	subnet_add(struct ctl_subnet *);
int	subnet_contains(struct subnet *, struct in_addr);
char *	subnet_delete(struct ctl_subnet *);
int	subnet_cmp(struct subnet *, struct subnet *);
int	subnet_free(struct subnet *);
char *	subnet_set(struct ctl_subnet_settings *);
char *	subnet_unset(struct ctl_subnet_settings *);
struct subnet *	subnet_find(struct in_addr, char *);
struct subnet *	subnet_add_lease(struct subnet *);
extern RB_HEAD(subnet_tree, subnet) subnets;
RB_PROTOTYPE(subnet_tree, subnet, subnets, subnet_cmp)

struct host *	subnet_find_host(struct subnet *, struct in_addr);


/*
 * Shared networks.
 */
struct shared_network {
	RB_ENTRY(shared_network) networks;
	char		*name;
	struct group	*group;

	struct host_mac_tree	hosts;
	struct lease_mac_tree	leases;
	struct subnet_tree	subnets;
	int			refcnt;	/* users: BPF, UDP, subnets, leases */
};

char *	shared_network_add(struct ctl_shared *);
char *	shared_network_delete(struct ctl_shared *);
int	shared_network_cmp(struct shared_network *, struct shared_network *);
int	shared_network_free(struct shared_network *);
struct shared_network *	shared_network_find(char *);
struct shared_network *	shared_network_from_relay(struct request *);
struct shared_network *	shared_network_use(struct shared_network *);
extern struct shared_network default_shared_network;
extern RB_HEAD(shared_network_tree, shared_network) shared_networks;
RB_PROTOTYPE(shared_network_tree, shared_network, networks, shared_network_cmp)

struct host *	shared_network_find_mac(struct request *);
struct subnet *	shared_network_find_subnet(struct shared_network *, struct in_addr);


/*
 * Ranges to allocate dynamic leases from.
 */
struct range {
	struct range		*next;
	struct in_addr		 lo;
	struct in_addr		 hi;
	u_int8_t		 freemap[1];
};

int	range_add(struct subnet *, struct in_addr, struct in_addr);
int	range_contains(struct range *, struct in_addr);
int	range_delete(struct subnet *, struct in_addr, struct in_addr);
void	range_free(struct subnet *, struct in_addr);


/*
 * Each request has parsed information about it here.
 */
struct request {
	void			*rcvd_on_bpf;
	void			*rcvd_on;
	struct shared_network	*shared;
	struct ether_header	*l2;
	struct ip		*l3;
	struct udphdr		*l4;
	struct bootp		*bootp;
	u_int8_t		*dhcp_opts[256];
};

struct reply {
	/* Stuff to be sent. */
	struct {
		struct ether_header	 l2;
		struct ip		 l3;
		struct udphdr		 l4;
		struct bootp		 bootp;
		u_int8_t		 option_space[MTU -
		    sizeof(struct ether_header) - sizeof(struct ip) -
		    sizeof(struct udphdr) - sizeof(struct bootp)];
	} __attribute__((packed)) pkt;

	/* Stuff NOT to be sent. */
	int			 off;
	int			 maxsize;
	struct lease		*lease;
	u_int8_t		*options[256];
	struct in_addr		*next_server;
	char			*sname;
	char			*filename;
	unsigned		 flags;
};
#define REPLY_BROADCAST_LOCAL	0x01
#define REPLY_TO_DHCPINFORM	0x02
#define REPLY_EXTEND_LEASE	0x04


/*
 * Statistics about the server operation.
 */
enum {
	STATS_LEASES_PRESENT,
	STATS_BOOTREQUESTS,
	STATS_BOOTREPLIES,
	STATS_DISCOVERS,
	STATS_OFFERS,
	STATS_REQUESTS,
	STATS_REQUESTS_INIT_REBOOT,
	STATS_REQUESTS_RENEWING,
	STATS_REQUESTS_REBINDING,
	STATS_REQUESTS_SELECTING,
	STATS_DECLINES,
	STATS_ACKS,
	STATS_NAKS,
	STATS_RELEASES,
	STATS_INFORMS,

	STATS_IP_NO_ADDRESS,
	STATS_IP_BAD_LEN,
	STATS_UDP_BAD_LEN,
	STATS_BOOTP_BAD_LEN,
	STATS_DHCP_BAD_LEN,
	STATS_DHCP_NOT_FOR_US,
	STATS_BOOTP_NOT_BOOTREQUEST,
	STATS_BOOTP_BAD_HTYPE,
	STATS_BOOTP_BAD_HLEN,
	STATS_BOOTP_BAD_RELAY,
	STATS_DHCP_BAD_MESSAGE_TYPE,
	STATS_DHCP_INVALID_OPTIONS,
	STATS_DHCP_DUPLICATE_OPTIONS,
	STATS_DHCP_NO_SPACE,
	STATS_DHCP_NOT_FOUND,

	STATS_DAEMON_STARTED,
	STATS__MAXIMUM
};
extern u_int64_t stats[STATS__MAXIMUM];

/*
 * imsg passing between dhcpd and its controllers
 * Priv/unpriv communication passes socket along with the original request,
 * which both sides use to determine which socket it actually is.
 *
 * Controller/server communication ends when controller says an empty IMSG_DONE
 * or the pipe breaks.  IMSG_ERROR is accompanied with a string error meessage.
 * On the server side, these messages are static strings, _NOT_ to be free(3)'d.
 * Their purpose is purely informative, no need to be precise.  That would be
 * the controller's job: it knows what was sent.
 */
enum {
	IMSG_DONE,
	IMSG_ERROR,

	/* Priv <-> unpriv. */
	IMSG_BPF,
	IMSG_UDP,

	/* Controller <-> server. */
	IMSG_SHARED_NETWORK_ADD,
	IMSG_SHARED_NETWORK_DELETE,
	IMSG_SHARED_NETWORK_LIST,

	IMSG_SUBNET_ADD,
	IMSG_SUBNET_DELETE,
	IMSG_SUBNET_LIST,
	IMSG_SUBNET_SET,
	IMSG_SUBNET_SHOW,
	IMSG_SUBNET_UNSET,

	IMSG_HOST_ADD,
	IMSG_HOST_DELETE,

	IMSG_LEASES_DUMP,
	IMSG_LEASE_RELEASE,

	IMSG_LISTEN_INTERFACE_ADD,
	IMSG_LISTEN_INTERFACE_DELETE,
	IMSG_LISTEN_INTERFACE_LIST,

	IMSG_LISTEN_ADDRESS_ADD,
	IMSG_LISTEN_ADDRESS_DELETE,
	IMSG_LISTEN_ADDRESS_LIST,

	IMSG_RELAY_ADD,
	IMSG_RELAY_DELETE,
	IMSG_RELAY_LIST,

	IMSG_GROUP_CREATE,
	IMSG_GROUP_LIST,
	IMSG_GROUP_SET,
	IMSG_GROUP_UNSET,

	IMSG_STATS,
};

/* bpf.c */
int	bpf_socket_open(char *);
int	ether_input(void *, size_t, struct request *);
int	ipv4_input(void *, size_t, struct request *);
int	udp_input(void *, size_t, struct request *);
int	ether_output(struct reply *, struct request *);
int	ipv4_output(struct reply *, struct request *);
int	udp_output(struct reply *, struct request *);

/* control.c */
int	control_init(char *, uid_t, gid_t);
void	control_accept(int, short, void *);
void	control_close(int);
void	control_dispatch(int, short, void *);
size_t	controllers(void);

/* interface.c */
int	rtsock_init(void);
void	rtsock_dispatch(int, short, void *);
size_t	interfaces(void);
ssize_t	interfaces_dump(struct ctl_interface **, ssize_t *);
ssize_t	interfaces_discover(void);
void	interfaces_destroy(void);
char *	interface_add(struct ctl_interface *);
char *	interface_delete(struct ctl_interface *);
void	interface_assign_bpf(char *, int);
void	ipv4_addr_assign_udp(u_int32_t *, int);
char *	ipv4_addr_add(struct ctl_address *);
char *	ipv4_addr_delete(struct ctl_address *);
ssize_t	ipv4_addr_dump(struct ctl_address **, ssize_t *);
struct in_addr	 ipv4_addr(void *);
struct in_addr	 destination(struct reply *, struct request *, u_int16_t *);

u_int32_t	 plen2mask32(u_int8_t);
int		 sendit(struct request *, struct reply *);
void		*bpf_address(struct request *);

/* lease.c */
void	lease_extend(struct reply *);
void	lease_whoisit(struct lease *, struct request *);

/* log.c */
void	log_init(int);
void	log_debug(const char *, ...);
void	log_info(const char *, ...);
void	log_warn(const char *, ...);
void	log_warnx(const char *, ...);
void	fatal(const char *);
void	fatalx(const char *);

#ifdef EBUG_IO
#define	log_debug_io(fmt, ...)	log_debug(fmt, __VA_ARGS__)
#else /* EBUG_IO */
#define log_debug_io(fmt, ...)	(void) 0
#endif /* EBUG_IO */

/* privsep.c */
void	privsep_init(int, int);
int	privileged_main(void);
int	unprivileged_ask_for_bpf(const char *);
int	unprivileged_ask_for_udp(u_int32_t);
void	unprivileged_dispatch(int, short, void *);

/* protocol_input.c */
int	dhcp_options_parse(u_int8_t *, size_t, u_int8_t **);
int	bootp_input(u_int8_t *, size_t, struct request *);

/* protocol_logic.c */
int	bootrequest(struct request *, void *, ssize_t);
int	dhcpdecline(struct request *);
int	dhcpdiscover(struct request *);
int	dhcpinform(struct request *);
int	dhcprelease(struct request *);
int	dhcprequest(struct request *);

/* protocol_output.c */
int	bootp_output(struct request *, struct reply *);
int	dhcp_output(struct request *, struct reply *);
int	dhcp_add_tlv(struct reply *, u_int8_t, u_int8_t, void *);
int	dhcp_fill_options(struct request *, struct reply *, struct group *);

/* unsatisfied.c */
void	unsatisfied_log(struct request *, const char *, char *);
void	unsatisfied_purge(void);
