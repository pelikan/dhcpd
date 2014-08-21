/*
 * Bootstrap Protocol (RFC 951)
 * Dynamic Host Configuration Protocol (RFC 2131)
 */
#define	BOOTP_SERVER_PORT	67
#define	BOOTP_CLIENT_PORT	68
#define	BOOTP_SNAME	64
#define	BOOTP_FILE	128
#define	BOOTP_VEND	64
struct bootp {
	u_int8_t	op;	/* Message op code / message type */
	u_int8_t	htype;	/* Hardware address type */
	u_int8_t	hlen;	/* Hardware address length */
	u_int8_t	hops;	/* Number of relay agent hops from client */
	u_int32_t	xid;	/* Transaction ID */
	u_int16_t	secs;	/* Seconds since the client began */
	u_int16_t	flags;	/* fig.2 */

	struct in_addr	ciaddr;	/* Client's IP address (if already in use) */
	struct in_addr	yiaddr;	/* Your IP address (to the client) */
	struct in_addr	siaddr;	/* Next server's in bootstrap IP address */
	struct in_addr	giaddr;	/* Relay agent's address (closest to client) */

	union {
		struct ether_addr	ether;
		u_int8_t		buf[16];
	}		chaddr;	/* Client's hardware address */

	char		sname[BOOTP_SNAME];	/* Server name \0 terminated */
	char		file[BOOTP_FILE];	/* Boot file \0 terminated */

	/* 'vend' or DHCP magic and options follow. */
};

enum {
	BOOTREQUEST = 1,
	BOOTREPLY = 2,
};

enum {
	HTYPE_ETHERNET = 1,
	HTYPE_IPSEC_TUNNEL = 31,	/* RFC 3456 */
};

#define	BOOTP_FLAG_BROADCAST	0x8000

enum {
	DHCP_OPT_NETWORK_MASK	= 1,
	DHCP_OPT_ROUTERS	= 3,
	DHCP_OPT_SERVERS_DNS	= 6,
	DHCP_OPT_HOSTNAME	= 12,
	DHCP_OPT_ADDR_REQUESTED	= 50,
	DHCP_OPT_ADDR_LEASETIME	= 51,
	DHCP_OPT_MESSAGE_TYPE	= 53,
	DHCP_OPT_SERVER_ID	= 54,
	DHCP_OPT_REQUEST_PARAMS	= 55,
	DHCP_OPT_T1_RENEW_TIME	= 58,
	DHCP_OPT_T2_REBIND_TIME	= 59,
	DHCP_OPT_VENDOR_CLASSID	= 60,
	DHCP_OPT_CLIENT_ID	= 61,	/* RFC 4361 */
	DHCP_OPT_TFTP_SNAME	= 66,
	DHCP_OPT_TFTP_FILENAME	= 67,
	DHCP_OPT_RAPID_COMMIT	= 80,	/* RFC 4039 */
	DHCP_OPT_RELAY_INFO	= 82,	/* RFC 3046 */
	DHCP_OPT_SYSTEM_ARCH	= 93,
	DHCP_OPT_NET_DEV_IFACE	= 94,
	DHCP_OPT_SERVERS_TFTP	= 150,	/* RFC 5859 */
	DHCP_OPT_END		= 255,
};

enum {
	DHCPDISCOVER	= 1,
	DHCPOFFER	= 2,
	DHCPREQUEST	= 3,
	DHCPDECLINE	= 4,
	DHCPACK		= 5,
	DHCPNAK		= 6,
	DHCPRELEASE	= 7,
	DHCPINFORM	= 8,
	DHCP__MAXIMUM	= 9,
};

#define DHCP_OPTION_START_MAGIC	(0x63825363)	/* network byte order */
