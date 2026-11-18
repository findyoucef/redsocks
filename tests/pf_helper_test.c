/* The helper protocol is testable without /dev/pf: invalid requests must fail
 * before ioctl, and channel closure must reap the child cleanly. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include "pf-helper.h"
int main(void)
{
	int pf = open("/dev/null", O_RDWR);
	assert(pf >= 0);
	int channel = pf_helper_start(pf);
	assert(channel >= 0);
	struct sockaddr_in destination;
	int pipefd[2];
	assert(pipe(pipefd) == 0);
	assert(pf_helper_lookup(channel, pipefd[0], &destination) == -1 && errno == EINVAL);
	int udp = socket(AF_INET, SOCK_DGRAM, 0);
	assert(udp >= 0);
	assert(pf_helper_lookup(channel, udp, &destination) == -1 && errno == EINVAL);
	int tcp = socket(AF_INET, SOCK_STREAM, 0);
	assert(tcp >= 0);
	assert(pf_helper_lookup(channel, tcp, &destination) == -1 && errno == EINVAL);
	// Repeated rejected requests do not break the channel or consume worker FDs.
	for (int i = 0; i < 100; i++)
		assert(pf_helper_lookup(channel, pipefd[0], &destination) == -1 && errno == EINVAL);
	pf_helper_stop(channel);
	close(pf); close(pipefd[0]); close(pipefd[1]); close(udp); close(tcp);
	puts("PASS: PF helper rejects pipes, UDP and unconnected TCP descriptors");
}
