#include <err.h>
#include <fcntl.h>
#include <unistd.h>

#include "../dhcpd.h"

#include "../bpf.c"
#include "../group.c"
#include "../interface.c"
#include "../lease.c"
#include "../log.c"
#include "../memory.c"
#include "../protocol_input.c"
#include "../protocol_logic.c"
#include "../protocol_output.c"
#include "../protocol_quirks.c"
#include "../range.c"
#include "../unsatisfied.c"

#include "harness.h"

int initialized;

int
LLVMFuzzerTestOneInput(const u_int8_t *data, size_t size)
{
	const u_int32_t magic = htonl(DHCP_OPTION_START_MAGIC);
	struct request req;
	union {
		unsigned char data[1518];
		struct {
			struct ether_header l2;
			struct ip l3;
			struct udphdr l4;
			struct bootp bootp;
			unsigned char dhcp[1];
		} p;
	} packet;

	if (!initialized) {
		log_init(1);
		set_defaults();
		++initialized;
	}

	memset(&packet, 0, sizeof packet);
	memset(&req, 0, sizeof req);
	req.l3 = &packet.p.l3;
	req.rcvd_on = &fake_address;
	req.shared = &default_shared_network;
	if (size % 2)
		packet.p.l3.ip_src.s_addr = INADDR_BROADCAST;
	else
		packet.p.l3.ip_src.s_addr = htonl(0xC0A80142);
	packet.p.bootp.op = 1;
	packet.p.bootp.htype = 1;
	packet.p.bootp.hlen = 6;
	packet.p.bootp.chaddr.buf[2] = 6;
	packet.p.bootp.xid = 0xDEADBEEF;
	packet.p.bootp.ciaddr.s_addr = htonl(0xC0A80142);
	packet.p.bootp.flags = packet.p.l3.ip_src.s_addr == INADDR_BROADCAST ?
	    BOOTP_FLAG_BROADCAST : 0;
	memcpy(&packet.p.dhcp, &magic, 4);
	packet.p.dhcp[4] = DHCP_OPT_MESSAGE_TYPE;
	packet.p.dhcp[5] = 1;
	memcpy(&packet.p.dhcp + 6, data, size);
	bootp_input((void *)&packet.p.bootp, sizeof packet.p.bootp + size + 6, &req);

	return 0;
}
