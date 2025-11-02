#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

int main(int argc, char *argv[])
{
	printf("PID: %d, UID: %d\n", getpid(), getuid());

	printf("Press any key to become cool :)");
	getchar();

	kill(getpid(), 67);

	execve(argv[1], (argv + 1), NULL);

	return 0;
}