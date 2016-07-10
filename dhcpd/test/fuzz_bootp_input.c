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

int
main(int argc, char *argv[])
{
	struct request req;
	unsigned char buf[256], l3[256];
	int fd;
	ssize_t len;

	if (argc != 2)
		errx(2, "argument");

	log_init(1);
	set_defaults();
	if ((fd = open(argv[1], O_RDONLY)) == -1)
		err(2, "open");
	if ((len = read(fd, buf, sizeof buf)) == -1)
		err(2, "read");

	memset(&l3, 0xFF, sizeof l3);
	memset(&req, 0, sizeof req);
	req.l3 = (void *)&l3;
	req.rcvd_on = &fake_address;
	req.shared = &default_shared_network;
	bootp_input(buf, len, &req);

	close(fd);
	return 0;
}
