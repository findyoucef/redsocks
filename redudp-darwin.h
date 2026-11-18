#ifndef REDSOCKS_REDUDP_DARWIN_H
#define REDSOCKS_REDUDP_DARWIN_H

#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>

struct redudp_fragments;
void redudp_free_fragments(struct redudp_fragments **head);

int redudp_open_tun(const char *name);
ssize_t redudp_read_tun(int fd, struct redudp_fragments **fragments, void *data, size_t capacity,
	struct sockaddr_in *client, struct sockaddr_in *destination);
ssize_t redudp_write_tun(int fd, const void *data, size_t length,
	const struct sockaddr_in *client, const struct sockaddr_in *remote);

#endif
