/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2018 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <stdlib.h>
#include <search.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "list.h"
#include "log.h"
#include "socks5.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "redudp.h"
#include "libc-compat.h"
#ifdef __APPLE__
#include "redudp-darwin.h"
#endif

#define redudp_log_error(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &(client)->clientaddr, get_destaddr(client), prio, ## msg)
#define redudp_log_errno(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &(client)->clientaddr, get_destaddr(client), prio, ## msg)

static void redudp_pkt_from_socks(int fd, short what, void *_arg);
static void redudp_drop_client(redudp_client *client);
static void redudp_fini_instance(redudp_instance *instance);
static int redudp_fini();
#ifdef __linux__
static int redudp_transparent(int fd);
#endif

typedef struct redudp_expected_assoc_reply_t {
	socks5_reply h;
	socks5_addr_ipv4 ip;
} PACKED redudp_expected_assoc_reply;

#ifdef __linux__
struct bound_udp4_key {
	struct in_addr sin_addr;
	uint16_t       sin_port;
};

struct bound_udp4 {
	struct bound_udp4_key key;
	int ref;
	int fd;
};

/***********************************************************************
 * Helpers
 */
// TODO: separate binding to privileged process (this operation requires uid-0)
static void* root_bound_udp4 = NULL; // to avoid two binds to same IP:port

static int bound_udp4_cmp(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct bound_udp4_key));
}

static void bound_udp4_mkkey(struct bound_udp4_key *key, const struct sockaddr_in *addr)
{
	memset(key, 0, sizeof(*key));
	key->sin_addr = addr->sin_addr;
	key->sin_port = addr->sin_port;
}

static int bound_udp4_get(const struct sockaddr_in *addr)
{
	struct bound_udp4_key key;
	struct bound_udp4 *node, **pnode;

	bound_udp4_mkkey(&key, addr);
	// I assume, that memory allocation for lookup is awful, so I use
	// tfind/tsearch pair instead of tsearch/check-result.
	pnode = tfind(&key, &root_bound_udp4, bound_udp4_cmp);
	if (pnode) {
		assert((*pnode)->ref > 0);
		(*pnode)->ref++;
		return (*pnode)->fd;
	}

	node = calloc(1, sizeof(*node));
	if (!node) {
		log_errno(LOG_ERR, "calloc");
		goto fail;
	}

	node->key = key;
	node->ref = 1;
	node->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (node->fd == -1) {
		log_errno(LOG_ERR, "socket");
		goto fail;
	}

	if (0 != redudp_transparent(node->fd))
		goto fail;

	if (0 != bind(node->fd, (struct sockaddr*)addr, sizeof(*addr))) {
		log_errno(LOG_ERR, "bind");
		goto fail;
	}

	pnode = tsearch(node, &root_bound_udp4, bound_udp4_cmp);
	if (!pnode) {
		log_errno(LOG_ERR, "tsearch(%p) == %p", node, pnode);
		goto fail;
	}
	assert(node == *pnode);

	return node->fd;

fail:
	if (node) {
		if (node->fd != -1)
			redsocks_close(node->fd);
		free(node);
	}
	return -1;
}

static void bound_udp4_put(const struct sockaddr_in *addr)
{
	struct bound_udp4_key key;
	struct bound_udp4 **pnode, *node;
	void *parent;

	bound_udp4_mkkey(&key, addr);
	pnode = tfind(&key, &root_bound_udp4, bound_udp4_cmp);
	assert(pnode && (*pnode)->ref > 0);

	node = *pnode;

	node->ref--;
	if (node->ref)
		return;

	parent = tdelete(node, &root_bound_udp4, bound_udp4_cmp);
	assert(parent);

	redsocks_close(node->fd); // expanding `pnode` to avoid use after free
	free(node);
}

static int redudp_transparent(int fd)
{
	int on = 1;
	int error = setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on));
	if (error)
		log_errno(LOG_ERR, "setsockopt(..., SOL_IP, IP_TRANSPARENT)");
	return error;
}

#endif /* __linux__ */

static int same_endpoint(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
	return a->sin_family == b->sin_family
	    && a->sin_addr.s_addr == b->sin_addr.s_addr
	    && a->sin_port == b->sin_port;
}

static int do_tproxy(redudp_instance* instance)
{
	return instance->config.destaddr.sin_addr.s_addr == 0;
}

static struct sockaddr_in* get_destaddr(redudp_client *client)
{
	return &client->destaddr;
}

static void redudp_fill_preamble(socks5_udp_preabmle *preamble, redudp_client *client)
{
	preamble->reserved = 0;
	preamble->frag_no = 0; /* fragmentation is not supported */
	preamble->addrtype = socks5_addrtype_ipv4;
	preamble->ip.addr = get_destaddr(client)->sin_addr.s_addr;
	preamble->ip.port = get_destaddr(client)->sin_port;
}

static struct evbuffer* socks5_mkmethods_plain_wrapper(void *p)
{
	int *do_password = p;
	return socks5_mkmethods_plain(*do_password);
}

static struct evbuffer* socks5_mkpassword_plain_wrapper(void *p)
{
	redudp_instance *self = p;
	return socks5_mkpassword_plain(self->config.login, self->config.password);
}

static struct evbuffer* socks5_mkassociate(void *p)
{
	struct sockaddr_in sa;
	UNUSED(p);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	return socks5_mkcommand_plain(socks5_cmd_udp_associate, &sa);
}

/***********************************************************************
 * Logic
 */
static void redudp_drop_client(redudp_client *client)
{
	redudp_log_error(client, LOG_INFO, "Dropping...");
	enqueued_packet *q, *tmp;
	if (event_initialized(&client->timeout)) {
		if (event_del(&client->timeout) == -1)
			redudp_log_errno(client, LOG_ERR, "event_del");
	}
	if (client->relay)
		redsocks_bufferevent_free(client->relay);
	if (event_initialized(&client->udprelay)) {
		int fd = event_get_fd(&client->udprelay);
		if (event_del(&client->udprelay) == -1)
			redudp_log_errno(client, LOG_ERR, "event_del");
		redsocks_close(fd);
	}
#ifdef __linux__
	if (client->sender_fd != -1)
		bound_udp4_put(&client->destaddr);
#endif
	list_for_each_entry_safe(q, tmp, &client->queue, list) {
		list_del(&q->list);
		free(q);
	}
	list_del(&client->list);
	free(client);
}

static int redudp_bump_timeout(redudp_client *client)
{
	struct timeval tv;
	tv.tv_sec = client->instance->config.udp_timeout;
	tv.tv_usec = 0;
	// TODO: implement udp_timeout_stream
	if (event_add(&client->timeout, &tv) != 0) {
		redudp_log_error(client, LOG_WARNING, "event_add(&client->timeout, ...)");
		return -1;
	}
	return 0;
}

static void redudp_forward_pkt(redudp_client *client, char *buf, size_t pktlen)
{
	socks5_udp_preabmle req;
	struct msghdr msg;
	struct iovec io[2];
	ssize_t outgoing, fwdlen = pktlen + sizeof(req);

	redudp_fill_preamble(&req, client);

	memset(&msg, 0, sizeof(msg));
	// The relay socket is connected; Darwin rejects another destination here.
	msg.msg_iov = io;
	msg.msg_iovlen = SIZEOF_ARRAY(io);

	io[0].iov_base = &req;
	io[0].iov_len = sizeof(req);
	io[1].iov_base = buf;
	io[1].iov_len = pktlen;

	outgoing = sendmsg(event_get_fd(&client->udprelay), &msg, 0);
	if (outgoing == -1) {
		redudp_log_errno(client, LOG_WARNING, "sendmsg: Can't forward packet, dropping it");
		return;
	}
	else if (outgoing != fwdlen) {
		redudp_log_error(client, LOG_WARNING, "sendmsg: I was sending %zd bytes, but only %zd were sent.", fwdlen, outgoing);
		return;
	}
}

static int redudp_enqeue_pkt(redudp_client *client, char *buf, size_t pktlen)
{
	enqueued_packet *q = NULL;

	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (client->queue_len >= client->instance->config.max_pktqueue) {
		redudp_log_error(client, LOG_WARNING, "There are already %u packets in queue. Dropping.",
		                 client->queue_len);
		return -1;
	}

	q = calloc(1, sizeof(enqueued_packet) + pktlen);
	if (!q) {
		redudp_log_errno(client, LOG_ERR, "Can't enqueue packet: calloc");
		return -1;
	}

	q->len = pktlen;
	memcpy(q->data, buf, pktlen);
	client->queue_len += 1;
	list_add_tail(&q->list, &client->queue);
	return 0;
}

static void redudp_flush_queue(redudp_client *client)
{
	enqueued_packet *q, *tmp;
	redudp_log_error(client, LOG_INFO, "Starting UDP relay");
	list_for_each_entry_safe(q, tmp, &client->queue, list) {
		redudp_forward_pkt(client, q->data, q->len);
		list_del(&q->list);
		free(q);
	}
	client->queue_len = 0;
	assert(list_empty(&client->queue));
}

static void redudp_read_assoc_reply(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	redudp_expected_assoc_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	int fd = -1;
	int error;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (read != sizeof(reply)) {
		redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %zu",
		                 read, sizeof(reply));
		goto fail;
	}

	if (reply.h.ver != socks5_ver || reply.h.reserved != 0) {
		redudp_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected reply version: %u", reply.h.ver);
		goto fail;
	}

	if (reply.h.status != socks5_status_succeeded) {
		redudp_log_error(client, LOG_NOTICE, "Socks5 server status: \"%s\" (%i)",
				socks5_status_to_str(reply.h.status), reply.h.status);
		goto fail;
	}

	if (reply.h.addrtype != socks5_addrtype_ipv4) {
		redudp_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected address type for UDP dgram destination: %u",
		                 reply.h.addrtype);
		goto fail;
	}

	client->udprelayaddr.sin_family = AF_INET;
	client->udprelayaddr.sin_port = reply.ip.port;
	client->udprelayaddr.sin_addr.s_addr = reply.ip.addr;
	if (reply.ip.addr == htonl(INADDR_ANY))
		client->udprelayaddr.sin_addr = client->instance->config.relayaddr.sin_addr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		redudp_log_errno(client, LOG_ERR, "socket");
		goto fail;
	}

	error = connect(fd, (struct sockaddr*)&client->udprelayaddr, sizeof(client->udprelayaddr));
	if (error) {
		redudp_log_errno(client, LOG_NOTICE, "connect");
		goto fail;
	}

	event_set(&client->udprelay, fd, EV_READ | EV_PERSIST, redudp_pkt_from_socks, client);
	fd = -1; // ownership belongs to client->udprelay now
	error = event_add(&client->udprelay, NULL);
	if (error) {
		redudp_log_errno(client, LOG_ERR, "event_add");
		goto fail;
	}

	redudp_flush_queue(client);
	// TODO: bufferevent_disable ?

	return;

fail:
	if (fd != -1)
		redsocks_close(fd);
	redudp_drop_client(client);
}

static void redudp_read_auth_reply(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	socks5_auth_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	int error;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (read != sizeof(reply)) {
		redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %zu",
		                 read, sizeof(reply));
		goto fail;
	}

	if (reply.ver != socks5_password_ver || reply.status != socks5_password_passed) {
		redudp_log_error(client, LOG_NOTICE, "Socks5 authentication error. Version: %u, error code: %u",
		                 reply.ver, reply.status);
		goto fail;
	}

	error = redsocks_write_helper_ex_plain(
			client->relay, NULL, socks5_mkassociate, NULL, 0, /* last two are ignored */
			sizeof(redudp_expected_assoc_reply), sizeof(redudp_expected_assoc_reply));
	if (error)
		goto fail;

	client->relay->readcb = redudp_read_assoc_reply;

	return;

fail:
	redudp_drop_client(client);
}

static void redudp_read_auth_methods(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
	socks5_method_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	const char *error = NULL;
	int ierror = 0;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (read != sizeof(reply)) {
		redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %zu",
		                 read, sizeof(reply));
		goto fail;
	}

	error = socks5_is_known_auth_method(&reply, do_password);
	if (error) {
		redudp_log_error(client, LOG_NOTICE, "socks5_is_known_auth_method: %s", error);
		goto fail;
	}
	else if (reply.method == socks5_auth_none) {
		ierror = redsocks_write_helper_ex_plain(
				client->relay, NULL, socks5_mkassociate, NULL, 0, /* last two are ignored */
				sizeof(redudp_expected_assoc_reply), sizeof(redudp_expected_assoc_reply));
		if (ierror)
			goto fail;

		client->relay->readcb = redudp_read_assoc_reply;
	}
	else if (reply.method == socks5_auth_password) {
		ierror = redsocks_write_helper_ex_plain(
				client->relay, NULL, socks5_mkpassword_plain_wrapper, client->instance, 0, /* last one is ignored */
				sizeof(socks5_auth_reply), sizeof(socks5_auth_reply));
		if (ierror)
			goto fail;

		client->relay->readcb = redudp_read_auth_reply;
	}

	return;

fail:
	redudp_drop_client(client);
}

static void redudp_relay_connected(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
	int error;
	char relayaddr_str[RED_INET_ADDRSTRLEN];
	redudp_log_error(client, LOG_DEBUG, "via %s", red_inet_ntop(&client->instance->config.relayaddr, relayaddr_str, sizeof(relayaddr_str)));

	if (!red_is_socket_connected_ok(buffev)) {
		redudp_log_errno(client, LOG_NOTICE, "red_is_socket_connected_ok");
		goto fail;
	}

	error = redsocks_write_helper_ex_plain(
			client->relay, NULL, socks5_mkmethods_plain_wrapper, &do_password, 0 /* does not matter */,
			sizeof(socks5_method_reply), sizeof(socks5_method_reply));
	if (error)
		goto fail;

	client->relay->readcb = redudp_read_auth_methods;
	client->relay->writecb = 0;
	//bufferevent_disable(buffev, EV_WRITE); // I don't want to check for writeability.
	return;

fail:
	redudp_drop_client(client);
}

static void redudp_relay_error(struct bufferevent *buffev, short what, void *_arg)
{
	redudp_client *client = _arg;
	// TODO: FIXME: Implement me
	redudp_log_error(client, LOG_NOTICE, "redudp_relay_error");
	redudp_drop_client(client);
}

static void redudp_timeout(int fd, short what, void *_arg)
{
	redudp_client *client = _arg;
	redudp_log_error(client, LOG_INFO, "Client timeout. First: %li, last_client: %li, last_relay: %li.",
	                 client->first_event, client->last_client_event, client->last_relay_event);
	redudp_drop_client(client);
}

static void redudp_first_pkt_from_client(redudp_instance *self, struct sockaddr_in *clientaddr, struct sockaddr_in *destaddr, char *buf, size_t pktlen)
{
	redudp_client *client = calloc(1, sizeof(*client));

	if (!client) {
		log_errno(LOG_WARNING, "calloc");
		return;
	}

	INIT_LIST_HEAD(&client->list);
	INIT_LIST_HEAD(&client->queue);
	client->instance = self;
	memcpy(&client->clientaddr, clientaddr, sizeof(*clientaddr));
	memcpy(&client->destaddr, destaddr, sizeof(client->destaddr));
	evtimer_set(&client->timeout, redudp_timeout, client);
	// XXX: self->relay_ss->init(client);

	client->sender_fd = -1; // it's postponed until socks-server replies to avoid trivial DoS

	client->relay = red_connect_relay(&client->instance->config.relayaddr,
	                                  redudp_relay_connected, redudp_relay_error, client);
	if (!client->relay)
		goto fail;

	if (redsocks_time(&client->first_event) == (time_t)-1)
		goto fail;
	client->last_client_event = client->first_event;
	if (redudp_bump_timeout(client) != 0)
		goto fail;

	if (redudp_enqeue_pkt(client, buf, pktlen) == -1)
		goto fail;

	list_add(&client->list, &self->clients);
	redudp_log_error(client, LOG_INFO, "got 1st packet from client");
	return;

fail:
	redudp_drop_client(client);
}

static void redudp_pkt_from_socks(int fd, short what, void *_arg)
{
	redudp_client *client = _arg;
	union {
		char buf[0xFFFF];
		socks5_udp_preabmle header;
	} pkt;
	ssize_t pktlen, fwdlen, outgoing;
	struct sockaddr_in udprelayaddr;

	assert(fd == event_get_fd(&client->udprelay));

	pktlen = red_recv_udp_pkt(fd, pkt.buf, sizeof(pkt.buf), &udprelayaddr, NULL);
	if (pktlen == -1)
		return;

	if (!same_endpoint(&udprelayaddr, &client->udprelayaddr)) {
		char buf[RED_INET_ADDRSTRLEN];
		redudp_log_error(client, LOG_NOTICE, "Got packet from unexpected address %s.",
		                 red_inet_ntop(&udprelayaddr, buf, sizeof(buf)));
		return;
	}

	if (pktlen < sizeof(pkt.header) || pkt.header.reserved != 0) {
		redudp_log_error(client, LOG_NOTICE, "Malformed SOCKS5 UDP header");
		return;
	}

	if (pkt.header.frag_no != 0) {
		// FIXME: does anybody need it?
		redudp_log_error(client, LOG_WARNING, "Got fragment #%u. Packet fragmentation is not supported!",
		                 pkt.header.frag_no);
		return;
	}

	if (pkt.header.addrtype != socks5_addrtype_ipv4) {
		redudp_log_error(client, LOG_NOTICE, "Got address type #%u instead of expected #%u (IPv4).",
		                 pkt.header.addrtype, socks5_addrtype_ipv4);
		return;
	}

	if (pkt.header.ip.port != get_destaddr(client)->sin_port ||
	    pkt.header.ip.addr != get_destaddr(client)->sin_addr.s_addr)
	{
		char buf[RED_INET_ADDRSTRLEN];
		struct sockaddr_in pktaddr = {
			.sin_family = AF_INET,
			.sin_addr   = { pkt.header.ip.addr },
			.sin_port   = pkt.header.ip.port,
		};
		redudp_log_error(client, LOG_NOTICE, "Socks5 server relayed packet from unexpected address %s.",
		                 red_inet_ntop(&pktaddr, buf, sizeof(buf)));
		return;
	}

	redsocks_time(&client->last_relay_event);
	if (redudp_bump_timeout(client) != 0) {
		redudp_drop_client(client);
		return;
	}

	int reply_fd = event_get_fd(&client->instance->listener);
#ifdef __linux__
	if (do_tproxy(client->instance) && client->sender_fd == -1) {
		client->sender_fd = bound_udp4_get(&client->destaddr);
		if (client->sender_fd == -1) {
			redudp_log_error(client, LOG_WARNING, "bound_udp4_get failure");
			return;
		}
	}

	if (do_tproxy(client->instance))
		reply_fd = client->sender_fd;
#endif

	fwdlen = pktlen - sizeof(pkt.header);
#ifdef __APPLE__
	if (client->instance->config.local_tun) {
		outgoing = redudp_write_tun(reply_fd, pkt.buf + sizeof(pkt.header), fwdlen,
			&client->clientaddr, &client->destaddr);
	} else
#endif
	outgoing = sendto(reply_fd,
	                  pkt.buf + sizeof(pkt.header), fwdlen, 0,
	                  (struct sockaddr*)&client->clientaddr, sizeof(client->clientaddr));
	if (outgoing != fwdlen) {
		redudp_log_error(client, LOG_WARNING, "sendto: I was sending %zd bytes, but only %zd were sent.",
		                 fwdlen, outgoing);
		return;
	}
}

static void redudp_pkt_from_client(int fd, short what, void *_arg)
{
	redudp_instance *self = _arg;
	struct sockaddr_in clientaddr, destaddr, *pdestaddr;
	char buf[0xFFFF]; // UDP packet can't be larger then that
	ssize_t pktlen;
	redudp_client *tmp, *client = NULL;

	pdestaddr = do_tproxy(self) ? &destaddr : NULL;

	assert(fd == event_get_fd(&self->listener));
#ifdef __APPLE__
	if (self->config.local_tun)
		pktlen = redudp_read_tun(fd, buf, sizeof(buf), &clientaddr, &destaddr);
	else
#endif
	pktlen = red_recv_udp_pkt(fd, buf, sizeof(buf), &clientaddr, pdestaddr);
	if (pktlen == -1)
		return;

	if (!pdestaddr)
		pdestaddr = &self->config.destaddr;

	// TODO: this lookup may be SLOOOOOW.
	list_for_each_entry(tmp, &self->clients, list) {
		if (same_endpoint(&clientaddr, &tmp->clientaddr) && same_endpoint(pdestaddr, &tmp->destaddr)) {
			client = tmp;
			break;
		}
	}

	if (client) {
		redsocks_time(&client->last_client_event);
		if (redudp_bump_timeout(client) != 0) {
			redudp_drop_client(client);
			return;
		}
		if (event_initialized(&client->udprelay)) {
			redudp_forward_pkt(client, buf, pktlen);
		}
		else {
			redudp_enqeue_pkt(client, buf, pktlen);
		}
	}
	else {
		redudp_first_pkt_from_client(self, &clientaddr, pdestaddr, buf, pktlen);
	}
}

/***********************************************************************
 * Init / shutdown
 */
static parser_entry redudp_entries[] =
{
	{ .key = "local_tun",  .type = pt_pchar },
	{ .key = "local_ip",   .type = pt_in_addr },
	{ .key = "local_port", .type = pt_uint16 },
	{ .key = "ip",         .type = pt_in_addr },
	{ .key = "port",       .type = pt_uint16 },
	{ .key = "login",      .type = pt_pchar },
	{ .key = "password",   .type = pt_pchar },
	{ .key = "dest_ip",    .type = pt_in_addr },
	{ .key = "dest_port",  .type = pt_uint16 },
	{ .key = "udp_timeout", .type = pt_uint16 },
	{ .key = "udp_timeout_stream", .type = pt_uint16 },
	{ }
};

static list_head instances = LIST_HEAD_INIT(instances);

static int redudp_onenter(parser_section *section)
{
	redudp_instance *instance = calloc(1, sizeof(*instance));
	if (!instance) {
		parser_error(section->context, "Not enough memory");
		return -1;
	}

	INIT_LIST_HEAD(&instance->list);
	INIT_LIST_HEAD(&instance->clients);
	instance->config.bindaddr.sin_family = AF_INET;
	instance->config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	instance->config.relayaddr.sin_family = AF_INET;
	instance->config.relayaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	instance->config.destaddr.sin_family = AF_INET;
	instance->config.max_pktqueue = 5;
	instance->config.udp_timeout = 30;
	instance->config.udp_timeout_stream = 180;

	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr =
			(strcmp(entry->key, "local_tun") == 0)  ? (void*)&instance->config.local_tun :
			(strcmp(entry->key, "local_ip") == 0)   ? (void*)&instance->config.bindaddr.sin_addr :
			(strcmp(entry->key, "local_port") == 0) ? (void*)&instance->config.bindaddr.sin_port :
			(strcmp(entry->key, "ip") == 0)         ? (void*)&instance->config.relayaddr.sin_addr :
			(strcmp(entry->key, "port") == 0)       ? (void*)&instance->config.relayaddr.sin_port :
			(strcmp(entry->key, "login") == 0)      ? (void*)&instance->config.login :
			(strcmp(entry->key, "password") == 0)   ? (void*)&instance->config.password :
			(strcmp(entry->key, "dest_ip") == 0)    ? (void*)&instance->config.destaddr.sin_addr :
			(strcmp(entry->key, "dest_port") == 0)  ? (void*)&instance->config.destaddr.sin_port :
			(strcmp(entry->key, "max_pktqueue") == 0) ? (void*)&instance->config.max_pktqueue :
			(strcmp(entry->key, "udp_timeout") == 0) ? (void*)&instance->config.udp_timeout:
			(strcmp(entry->key, "udp_timeout_stream") == 0) ? (void*)&instance->config.udp_timeout_stream :
			NULL;
	section->data = instance;
	return 0;
}

static int redudp_onexit(parser_section *section)
{
	redudp_instance *instance = section->data;

	section->data = NULL;
	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr = NULL;

	instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);
	instance->config.relayaddr.sin_port = htons(instance->config.relayaddr.sin_port);
	instance->config.destaddr.sin_port = htons(instance->config.destaddr.sin_port);
	if (instance->config.local_tun && (instance->config.destaddr.sin_addr.s_addr || instance->config.bindaddr.sin_port)) {
		parser_error(section->context, "local_tun cannot be combined with dest_ip/dest_port or local_port");
		return -1;
	}
#ifdef __APPLE__
	if (!instance->config.local_tun && !instance->config.destaddr.sin_addr.s_addr) {
		parser_error(section->context, "macOS UDP requires dest_ip/dest_port or local_tun");
		return -1;
	}
#else
	if (instance->config.local_tun) {
		parser_error(section->context, "local_tun requires macOS");
		return -1;
	}
#endif

	if (!instance->config.udp_timeout ||
	    (!!instance->config.destaddr.sin_addr.s_addr != !!instance->config.destaddr.sin_port)) {
		parser_error(section->context, "udp_timeout must be positive; specify both dest_ip and dest_port, or neither");
		return -1;
	}

	if (instance->config.udp_timeout_stream < instance->config.udp_timeout) {
		parser_error(section->context, "udp_timeout_stream should be not less then udp_timeout");
		return -1;
	}

	list_add(&instance->list, &instances);

	return 0;
}

static int redudp_init_instance(redudp_instance *instance)
{
	/* FIXME: redudp_fini_instance is called in case of failure, this
	 *        function will remove instance from instances list - result
	 *        looks ugly.
	 */
	int error;
	int fd = -1;

#ifdef __APPLE__
	if (instance->config.local_tun) {
		fd = redudp_open_tun(instance->config.local_tun);
		if (fd == -1) {
			log_errno(LOG_ERR, "open %s", instance->config.local_tun);
			goto fail;
		}
		log_error(LOG_NOTICE, "UDP capture on %s; configure its IPv4 address and MTU before routing traffic", instance->config.local_tun);
	} else
#endif
	{
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd == -1) {
			log_errno(LOG_ERR, "socket");
			goto fail;
		}

		if (do_tproxy(instance)) {
#ifdef __linux__
			int on = 1;
			char buf[RED_INET_ADDRSTRLEN];
			// iptables TPROXY target does not send packets to non-transparent sockets
			if (0 != redudp_transparent(fd))
				goto fail;

			error = setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on));
			if (error) {
				log_errno(LOG_ERR, "setsockopt(listener, SOL_IP, IP_RECVORIGDSTADDR)");
				goto fail;
			}

			log_error(LOG_DEBUG, "redudp @ %s: TPROXY", red_inet_ntop(&instance->config.bindaddr, buf, sizeof(buf)));
#endif
		}
		else {
			char buf1[RED_INET_ADDRSTRLEN], buf2[RED_INET_ADDRSTRLEN];
			log_error(LOG_DEBUG, "redudp @ %s: destaddr=%s",
				red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)),
				red_inet_ntop(&instance->config.destaddr, buf2, sizeof(buf2)));
		}

		error = bind(fd, (struct sockaddr*)&instance->config.bindaddr, sizeof(instance->config.bindaddr));
		if (error) {
			log_errno(LOG_ERR, "bind");
			goto fail;
		}

		error = fcntl_nonblock(fd);
		if (error) {
			log_errno(LOG_ERR, "fcntl");
			goto fail;
		}
	}

	event_set(&instance->listener, fd, EV_READ | EV_PERSIST, redudp_pkt_from_client, instance);
	error = event_add(&instance->listener, NULL);
	if (error) {
		log_errno(LOG_ERR, "event_add");
		goto fail;
	}

	return 0;

fail:
	redudp_fini_instance(instance);

	if (fd != -1) {
		redsocks_close(fd);
	}

	return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void redudp_fini_instance(redudp_instance *instance)
{
	if (!list_empty(&instance->clients)) {
		redudp_client *tmp, *client = NULL;

		log_error(LOG_WARNING, "There are connected clients during shutdown! Disconnecting them.");
		list_for_each_entry_safe(client, tmp, &instance->clients, list) {
			redudp_drop_client(client);
		}
	}

	if (event_initialized(&instance->listener)) {
		if (event_del(&instance->listener) != 0)
			log_errno(LOG_WARNING, "event_del");
		redsocks_close(event_get_fd(&instance->listener));
		memset(&instance->listener, 0, sizeof(instance->listener));
	}

	list_del(&instance->list);

	free(instance->config.login);
	free(instance->config.password);
	free(instance->config.local_tun);

	memset(instance, 0, sizeof(*instance));
	free(instance);
}

static int redudp_init()
{
	redudp_instance *tmp, *instance = NULL;

	// TODO: init debug_dumper

	list_for_each_entry_safe(instance, tmp, &instances, list) {
		if (redudp_init_instance(instance) != 0)
			goto fail;
	}

	return 0;

fail:
	redudp_fini();
	return -1;
}

static int redudp_fini()
{
	redudp_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list)
		redudp_fini_instance(instance);

	return 0;
}

static parser_section redudp_conf_section =
{
	.name    = "redudp",
	.entries = redudp_entries,
	.onenter = redudp_onenter,
	.onexit  = redudp_onexit
};

app_subsys redudp_subsys =
{
	.init = redudp_init,
	.fini = redudp_fini,
	.conf_section = &redudp_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
