/* Darwin privilege separation: only NAT lookup of a passed TCP socket is
 * permitted. The worker cannot submit arbitrary ioctl requests or PF rules. */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "pf-darwin.h"
#include "pf-helper.h"

static pid_t helper_pid = -1;
struct lookup_reply {
	int error;
	struct sockaddr_in destination;
};

static void serve(int channel, int pf)
{
	for (;;) {
		char byte;
		struct iovec iov = {&byte, 1};
		union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } control;
		struct msghdr msg = {0};
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.bytes;
		msg.msg_controllen = sizeof(control);
		ssize_t received = recvmsg(channel, &msg, 0);
		if (received < 0 && errno == EINTR)
			continue;
		if (received <= 0)
			break;
		struct lookup_reply reply = {.error = EINVAL};
		int fd = -1, count = 0;
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
				continue;
			size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
			for (size_t i = 0; i + sizeof(int) <= bytes; i += sizeof(int)) {
				int passed;
				memcpy(&passed, (char*)CMSG_DATA(cmsg) + i, sizeof(passed));
				if (++count == 1)
					fd = passed;
				else
					close(passed);
			}
		}
		if (fd >= 0) {
			struct sockaddr_in source, local;
			socklen_t slen = sizeof(source), llen = sizeof(local), tlen = sizeof(int);
			int type;
			if (count == 1 && !(msg.msg_flags & MSG_CTRUNC) &&
			    getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tlen) == 0 && type == SOCK_STREAM &&
			    getpeername(fd, (struct sockaddr*)&source, &slen) == 0 &&
			    getsockname(fd, (struct sockaddr*)&local, &llen) == 0 &&
			    slen == sizeof(source) && llen == sizeof(local) &&
			    source.sin_family == AF_INET && local.sin_family == AF_INET) {
				struct pfioc_natlook nl = {0};
				nl.saddr.v4 = source.sin_addr;
				nl.sport = source.sin_port;
				nl.daddr.v4 = local.sin_addr;
				nl.dport = local.sin_port;
				nl.af = AF_INET;
				nl.proto = IPPROTO_TCP;
				nl.direction = PF_OUT;
				int result = ioctl(pf, DIOCNATLOOK, &nl);
				if (result && errno == ENOENT) {
					nl.direction = PF_IN;
					result = ioctl(pf, DIOCNATLOOK, &nl);
				}
				reply.error = result ? errno : 0;
				if (!result) {
					reply.destination.sin_len = sizeof(reply.destination);
					reply.destination.sin_family = AF_INET;
					reply.destination.sin_addr = nl.rdaddr.v4;
					reply.destination.sin_port = nl.rdport;
				}
			}
			close(fd);
		}
		if (send(channel, &reply, sizeof(reply), 0) != sizeof(reply))
			break;
	}
	_exit(0);
}

int pf_helper_start(int pf)
{
	int pair[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair))
		return -1;
	int on = 1;
	setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
	setsockopt(pair[1], SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
	/* The worker must not hang if its helper is stopped or dies. */
	struct timeval timeout = {2, 0};
	setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	helper_pid = fork();
	if (helper_pid == -1) {
		int saved = errno;
		close(pair[0]); close(pair[1]);
		errno = saved;
		return -1;
	}
	if (!helper_pid) {
		/* Discard inherited listeners, tunnels, log files and event queues. */
		int limit = getdtablesize();
		for (int fd = 0; fd < limit; fd++)
			if (fd != pair[1] && fd != pf)
				close(fd);
		serve(pair[1], pf);
	}
	close(pair[1]);
	return pair[0];
}

int pf_helper_lookup(int channel, int connection, struct sockaddr_in *destination)
{
	char byte = 0;
	struct iovec iov = {&byte, 1};
	union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
	struct msghdr msg = {0};
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.bytes;
	msg.msg_controllen = sizeof(control);
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(connection));
	memcpy(CMSG_DATA(cmsg), &connection, sizeof(connection));
	if (sendmsg(channel, &msg, 0) != 1)
		return -1;
	struct lookup_reply reply;
	ssize_t size;
	do { size = recv(channel, &reply, sizeof(reply), 0); } while (size < 0 && errno == EINTR);
	if (size != sizeof(reply)) {
		/* A late response must never be mistaken for another connection. */
		shutdown(channel, SHUT_RDWR);
		errno = EIO;
		return -1;
	}
	if (reply.error) {
		errno = reply.error;
		return -1;
	}
	*destination = reply.destination;
	return 0;
}

void pf_helper_stop(int channel)
{
	close(channel);
	if (helper_pid > 0) {
		while (waitpid(helper_pid, NULL, 0) < 0 && errno == EINTR) {}
		helper_pid = -1;
	}
}
