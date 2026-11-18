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

#include "utils.h"
#include "redudp-darwin.h"

/* Public kernel-control transport; the SDK omits the utun-specific header.
 * Reference: apple-oss-distributions/xnu, bsd/net/if_utun.h. */
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME 2

int redudp_open_tun(const char *name)
{
	char *end;
	errno = 0;
	unsigned long unit = strtoul(name + (strlen(name) >= 4 ? 4 : 0), &end, 10);
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

ssize_t redudp_read_tun(int fd, void *data, size_t capacity,
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
	    total < header + 8 || total > (size_t)received - 4 ||
	    ip[9] != IPPROTO_UDP || (read16(ip + 6) & 0x3fff))
		goto malformed;
	const uint8_t *udp = ip + header;
	size_t length = read16(udp + 4);
	if (length < 8 || length != total - header || length - 8 > capacity)
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
