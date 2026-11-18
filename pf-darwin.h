#ifndef REDSOCKS_PF_DARWIN_H
#define REDSOCKS_PF_DARWIN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

/*
 * The macOS SDK does not publish net/pfvar.h. These declarations describe
 * only the DIOCNATLOOK ABI, rather than importing Apple's private headers.
 * Reference: apple-oss-distributions/xnu, bsd/net/pfvar.h, pfioc_natlook.
 * https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h
 *
 * Each port occupies the first two bytes of a four-byte pf_state_xport
 * union. The reserved halves below preserve that layout on Intel and arm64.
 */
union redsocks_pf_addr {
	struct in_addr v4;
	struct in6_addr v6;
};

struct pfioc_natlook {
	union redsocks_pf_addr saddr, daddr, rsaddr, rdaddr;
	uint16_t sport, sport_reserved;
	uint16_t dport, dport_reserved;
	uint16_t rsport, rsport_reserved;
	uint16_t rdport, rdport_reserved;
	sa_family_t af;
	uint8_t proto;
	uint8_t proto_variant;
	uint8_t direction;
};

/* C99 compile-time checks: an incompatible layout changes the ioctl number. */
typedef char redsocks_pf_size_check[sizeof(struct pfioc_natlook) == 84 ? 1 : -1];
typedef char redsocks_pf_port_check[offsetof(struct pfioc_natlook, sport) == 64 ? 1 : -1];
typedef char redsocks_pf_direction_check[offsetof(struct pfioc_natlook, direction) == 83 ? 1 : -1];

#define PF_IN 1
#define PF_OUT 2
#define DIOCNATLOOK _IOWR('D', 23, struct pfioc_natlook)

#endif
