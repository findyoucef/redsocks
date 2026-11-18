/* Exercise the actual utun packet reader using a datagram socket pair. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "redudp-darwin.h"

/* Only interface creation needs this project helper; these tests inject wire
 * packets directly and never create or reconfigure a network interface. */
int fcntl_nonblock(int fd) { return fcntl(fd, F_SETFL, O_NONBLOCK); }

static void put16(uint8_t *p, unsigned n) { p[0] = n >> 8; p[1] = n; }
static void fragment(int fd, unsigned id, unsigned offset, int more, const uint8_t *data, size_t size)
{
	uint8_t packet[128] = {0};
	uint32_t family = htonl(AF_INET);
	memcpy(packet, &family, 4);
	packet[4] = 0x45;
	put16(packet + 6, 20 + size);
	put16(packet + 8, id);
	put16(packet + 10, offset / 8 | (more ? 0x2000 : 0));
	packet[13] = IPPROTO_UDP;
	packet[16] = 127; packet[19] = 1;
	packet[20] = 198; packet[21] = 18; packet[23] = 1;
	memcpy(packet + 24, data, size);
	assert(send(fd, packet, 24 + size, 0) == 24 + size);
}

int main(void)
{
	int pair[2];
	assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0);
	struct redudp_fragments *state = NULL;
	struct sockaddr_in client, destination;
	uint8_t udp[32] = {0}, out[128];
	put16(udp, 1234); put16(udp + 2, 5678); put16(udp + 4, sizeof(udp));
	memcpy(udp + 8, "abcdefghijklmnopqrstuvwx", 24);
#define READ() redudp_read_tun(pair[1], &state, out, sizeof(out), &client, &destination)
	// Tail first, exact duplicate, then head: deliver only once complete.
	fragment(pair[0], 1, 16, 0, udp + 16, 16); assert(READ() == -1);
	fragment(pair[0], 1, 16, 0, udp + 16, 16); assert(READ() == -1);
	fragment(pair[0], 1, 0, 1, udp, 16); assert(READ() == 24);
	assert(memcmp(out, udp + 8, 24) == 0);
	assert(ntohs(client.sin_port) == 1234 && ntohs(destination.sin_port) == 5678);
	// Conflicting overlap poisons the entire assembly, including later tails.
	fragment(pair[0], 2, 0, 1, udp, 16); assert(READ() == -1);
	uint8_t bad[16]; memcpy(bad, udp + 8, 16); bad[0] ^= 1;
	fragment(pair[0], 2, 8, 1, bad, 16); assert(READ() == -1);
	fragment(pair[0], 2, 16, 0, udp + 16, 16); assert(READ() == -1);
	// Reject non-final fragments that aren't multiples of eight bytes.
	fragment(pair[0], 3, 0, 1, udp, 15); assert(READ() == -1);
	// Separate IDs may interleave.
	fragment(pair[0], 4, 0, 1, udp, 16); assert(READ() == -1);
	fragment(pair[0], 5, 16, 0, udp + 16, 16); assert(READ() == -1);
	fragment(pair[0], 4, 16, 0, udp + 16, 16); assert(READ() == 24);
	fragment(pair[0], 5, 0, 1, udp, 16); assert(READ() == 24);
	// An unfragmented UDP packet uses the same validation and output path.
	fragment(pair[0], 6, 0, 0, udp, 32); assert(READ() == 24);
	// State is bounded: a flood cannot allocate indefinitely.
	for (unsigned i = 100; i < 140; i++) {
		fragment(pair[0], i, 0, 1, udp, 16); assert(READ() == -1);
	}
	fragment(pair[0], 139, 16, 0, udp + 16, 16); assert(READ() == -1);
	redudp_free_fragments(&state);
	assert(!state);
	close(pair[0]); close(pair[1]);
	puts("PASS: utun reassembly, duplicates, overlaps, interleaving and bounds");
}
