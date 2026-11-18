/* IPv4 UDP packet I/O for Darwin's utun control socket. */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "utils.h"
#include "redudp-darwin.h"

/* Public kernel-control transport; the SDK omits the utun-specific header.
 * Reference: apple-oss-distributions/xnu, bsd/net/if_utun.h. */
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2

int redudp_open_tun(const char *name)
{
	if (strncmp(name, "utun", 4) != 0 || !name[4]) {
		errno = EINVAL;
		return -1;
	}
	char *end;
	errno = 0;
	unsigned long unit = strtoul(name + 4, &end, 10);
	char canonical[IFNAMSIZ];
	snprintf(canonical, sizeof(canonical), "utun%lu", unit);
	if (errno || unit >= UINT32_MAX || *end || strcmp(name, canonical) != 0) {
		errno = EINVAL;
		return -1;
	}
	int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd == -1)
		return -1;
	struct ctl_info info;
	memset(&info, 0, sizeof(info));
	strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
	if (ioctl(fd, CTLIOCGINFO, &info) == -1)
		goto fail;
	struct sockaddr_ctl address;
	memset(&address, 0, sizeof(address));
	address.sc_len = sizeof(address);
	address.sc_family = AF_SYSTEM;
	address.ss_sysaddr = AF_SYS_CONTROL;
	address.sc_id = info.ctl_id;
	address.sc_unit = (uint32_t)unit + 1;
	if (connect(fd, (struct sockaddr*)&address, sizeof(address)) == -1)
		goto fail;
	char actual[IFNAMSIZ] = {0};
	socklen_t length = sizeof(actual);
	if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, actual, &length) == -1)
		goto fail;
	if (strcmp(actual, name) != 0) {
		errno = EINVAL;
		goto fail;
	}
	if (fcntl_nonblock(fd) != 0)
		goto fail;
	return fd;
fail: {
	int saved = errno;
	close(fd);
	errno = saved;
	return -1;
}
}

static uint16_t read16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static void write16(uint8_t *p, uint16_t value)
{
	p[0] = value >> 8;
	p[1] = value & 0xff;
}

/* Bound each interface to 32 incomplete datagrams (about 2.4 MiB), with
 * a fixed lifetime. Conflicting overlaps poison the ID until it expires. */
struct redudp_fragments {
	struct redudp_fragments *next;
	struct timespec created;
	uint8_t key[10]; /* source, destination, IPv4 ID; protocol is always UDP */
	uint8_t data[65515];
	uint8_t present[8192];
	size_t count, end, highest;
	int poisoned;
};

void redudp_free_fragments(struct redudp_fragments **head)
{
	while (*head) {
		struct redudp_fragments *next = (*head)->next;
		free(*head);
		*head = next;
	}
}

static ssize_t reassemble(struct redudp_fragments **head, const uint8_t *ip,
	size_t header, size_t total, uint8_t *output)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -1;
	uint8_t key[10];
	memcpy(key, ip + 12, 8);
	memcpy(key + 8, ip + 4, 2);
	struct redudp_fragments **cursor = head, *entry = NULL;
	size_t entries = 0;
	while (*cursor) {
		struct redudp_fragments *item = *cursor;
		if (now.tv_sec - item->created.tv_sec >= 30) {
			*cursor = item->next;
			free(item);
			continue;
		}
		if (memcmp(item->key, key, sizeof(key)) == 0)
			entry = item;
		entries++;
		cursor = &item->next;
	}
	size_t offset = (read16(ip + 6) & 0x1fff) * 8;
	size_t length = total - header;
	int more = read16(ip + 6) & 0x2000;
	if (!length || offset + length > 65515 || (more && length % 8))
		return -1;
	if (!entry) {
		if (entries >= 32)
			return -1;
		entry = calloc(1, sizeof(*entry));
		if (!entry)
			return -1;
		memcpy(entry->key, key, sizeof(key));
		entry->created = now;
		entry->next = *head;
		*head = entry;
	}
	if (entry->poisoned)
		return -1;
	if ((entry->end && (offset + length > entry->end || (!more && offset + length != entry->end))) ||
	    (!more && offset + length < entry->highest))
		goto conflict;
	if (!more)
		entry->end = offset + length;
	if (offset + length > entry->highest)
		entry->highest = offset + length;
	for (size_t i = 0; i < length; i++) {
		size_t pos = offset + i;
		uint8_t bit = 1u << (pos % 8);
		if (entry->present[pos / 8] & bit) {
			if (entry->data[pos] != ip[header + i])
				goto conflict;
		} else {
			entry->present[pos / 8] |= bit;
			entry->data[pos] = ip[header + i];
			entry->count++;
		}
	}
	if (!entry->end || entry->count != entry->end)
		return -1;
	size_t result = entry->end;
	memcpy(output, entry->data, result);
	for (cursor = head; *cursor != entry; cursor = &(*cursor)->next) {}
	*cursor = entry->next;
	free(entry);
	return result;
conflict:
	entry->poisoned = 1;
	return -1;
}

ssize_t redudp_read_tun(int fd, struct redudp_fragments **fragments, void *data, size_t capacity,
	struct sockaddr_in *client, struct sockaddr_in *destination)
{
	uint8_t packet[4 + 65535];
	ssize_t received = read(fd, packet, sizeof(packet));
	if (received == -1)
		return -1;
	uint32_t family;
	if (received < 4 + 20 + 8)
		goto malformed;
	memcpy(&family, packet, sizeof(family));
	const uint8_t *ip = packet + 4;
	size_t header = (ip[0] & 15) * 4;
	size_t total = read16(ip + 2);
	if (ntohl(family) != AF_INET || (ip[0] >> 4) != 4 || header < 20 ||
	    total < header || total > (size_t)received - 4 ||
	    ip[9] != IPPROTO_UDP)
		goto malformed;
	uint8_t assembled[65515];
	const uint8_t *udp = ip + header;
	size_t udp_size = total - header;
	if (read16(ip + 6) & 0x3fff) {
		ssize_t size = reassemble(fragments, ip, header, total, assembled);
		if (size < 0)
			goto malformed;
		udp = assembled;
		udp_size = size;
	}
	if (udp_size < 8)
		goto malformed;
	size_t length = read16(udp + 4);
	if (length < 8 || length != udp_size || length - 8 > capacity)
		goto malformed;
	memset(client, 0, sizeof(*client));
	memset(destination, 0, sizeof(*destination));
	client->sin_len = destination->sin_len = sizeof(*client);
	client->sin_family = destination->sin_family = AF_INET;
	memcpy(&client->sin_addr, ip + 12, 4);
	memcpy(&destination->sin_addr, ip + 16, 4);
	memcpy(&client->sin_port, udp, 2);
	memcpy(&destination->sin_port, udp + 2, 2);
	memcpy(data, udp + 8, length - 8);
	return length - 8;
malformed:
	errno = EPROTO;
	return -1;
}

ssize_t redudp_write_tun(int fd, const void *data, size_t length,
	const struct sockaddr_in *client, const struct sockaddr_in *remote)
{
	if (length > 65535 - 28) {
		errno = EMSGSIZE;
		return -1;
	}
	uint8_t header[4 + 20 + 8] = {0};
	uint32_t family = htonl(AF_INET);
	memcpy(header, &family, sizeof(family));
	uint8_t *ip = header + 4;
	ip[0] = 0x45;
	write16(ip + 2, (uint16_t)(28 + length));
	ip[8] = 64;
	ip[9] = IPPROTO_UDP;
	memcpy(ip + 12, &remote->sin_addr, 4);
	memcpy(ip + 16, &client->sin_addr, 4);
	uint32_t checksum = 0;
	for (size_t i = 0; i < 20; i += 2)
		checksum += read16(ip + i);
	while (checksum >> 16)
		checksum = (checksum & 0xffff) + (checksum >> 16);
	write16(ip + 10, (uint16_t)~checksum);
	uint8_t *udp = ip + 20;
	memcpy(udp, &remote->sin_port, 2);
	memcpy(udp + 2, &client->sin_port, 2);
	write16(udp + 4, (uint16_t)(8 + length));
	/* A zero UDP checksum is permitted for IPv4. The IP checksum is above. */
	struct iovec parts[] = {{header, sizeof(header)}, {(void*)data, length}};
	ssize_t written = writev(fd, parts, 2);
	if (written == -1)
		return -1;
	if ((size_t)written != sizeof(header) + length) {
		errno = EIO;
		return -1;
	}
	return length;
}
