#include <fcntl.h>
#include <unistd.h>

#include "../parser.c"

/* Reads a list of IPv4 addresses from the argument file and prints them out. */
int
main(int argc, const char *argv[])
{
	int fd;

	if (argc != 2)
		errx(2, "argument");

	if ((fd = open(argv[1], O_RDONLY)) == -1)
		err(2, "open");
	res.opt_length = read(fd, res.opt_value, sizeof res.opt_value);
	if (res.opt_length == -1)
		err(2, "read");
	parse_ip_list();

	for (size_t i = 0; i < res.ipv4_list_cnt; ++i) {
		puts(inet_ntoa(res.ipv4_list[i]));
	}

	close(fd);
	return (0);
}
