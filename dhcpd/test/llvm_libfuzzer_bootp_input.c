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
	struct request req;
	unsigned char l3[256];

	if (!initialized) {
		log_init(1);
		set_defaults();
		++initialized;
	}

	memset(&l3, 0xFF, sizeof l3);
	memset(&req, 0, sizeof req);
	req.l3 = (void *)&l3;
	req.rcvd_on = &fake_address;
	req.shared = &default_shared_network;
	bootp_input(data, size, &req);

	return 0;
}
