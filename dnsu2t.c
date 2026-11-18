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
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>

#include "list.h"
#include "log.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "dnsu2t.h"
#include "utils.h"

#define dnsu2t_log_error(prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &clientaddr, &self->config.bindaddr, prio, ## msg)
#define dnsu2t_log_errno(prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &clientaddr, &self->config.bindaddr, prio, ## msg)

static void dnsu2t_fini_instance(dnsu2t_instance *instance);
static int dnsu2t_fini();
static void dnsu2t_close_relay(dnsu2t_instance *self);

typedef struct inflight_req_t {
	list_head list;
	uint16_t id;
	struct sockaddr_in clientaddr;
} inflight_req;

static void dnsu2t_close_relay(dnsu2t_instance *self)
{
	if (self->relay) {
		redsocks_bufferevent_free(self->relay);
		self->relay = NULL;
	}
	inflight_req *req, *tmp;
	list_for_each_entry_safe(req, tmp, &self->requests, list) {
		list_del(&req->list);
		free(req);
	}
	self->inflight_count = 0;
	if (event_initialized(&self->listener) && event_add(&self->listener, NULL))
		log_errno(LOG_ERR, "event_add");
}

static void dnsu2t_relay_error(struct bufferevent *bev, short what, void *arg)
{
	dnsu2t_instance *self = arg;
	log_error(LOG_DEBUG, "DNS TCP relay closed: " event_fmt_str, event_fmt(what));
	dnsu2t_close_relay(self);
}

static void dnsu2t_relay_read(struct bufferevent *bev, void *arg)
{
	dnsu2t_instance *self = arg;
	while (EVBUFFER_LENGTH(bev->input) >= 2) {
		uint16_t size;
		memcpy(&size, EVBUFFER_DATA(bev->input), sizeof(size));
		size_t length = ntohs(size);
		if (length <= sizeof(dns_header)) {
			log_error(LOG_NOTICE, "malformed DNS TCP response");
			dnsu2t_close_relay(self);
			return;
		}
		if (EVBUFFER_LENGTH(bev->input) < length + 2)
			return;
		const unsigned char *packet = EVBUFFER_DATA(bev->input) + 2;
		uint16_t id;
		memcpy(&id, packet, sizeof(id));
		inflight_req *req, *tmp;
		list_for_each_entry_safe(req, tmp, &self->requests, list) {
			if (req->id != id)
				continue;
			if (sendto(event_get_fd(&self->listener), packet, length, 0,
			           (struct sockaddr*)&req->clientaddr, sizeof(req->clientaddr)) == -1)
				log_errno(LOG_WARNING, "DNS UDP reply");
			list_del(&req->list);
			free(req);
			self->inflight_count--;
			break;
		}
		evbuffer_drain(bev->input, length + 2);
		if (self->inflight_count < self->config.inflight_max && event_add(&self->listener, NULL))
			log_errno(LOG_ERR, "event_add");
	}
}

static void dnsu2t_relay_connected(struct bufferevent *bev, void *arg)
{
	dnsu2t_instance *self = arg;
	if (!red_is_socket_connected_ok(bev)) {
		dnsu2t_close_relay(self);
		return;
	}
	bufferevent_setcb(bev, dnsu2t_relay_read, NULL, dnsu2t_relay_error, self);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
}

static void dnsu2t_pkt_from_client(int fd, short what, void *arg)
{
	dnsu2t_instance *self = arg;
	struct sockaddr_in clientaddr;
	dns_tcp_pkt packet;
	ssize_t length = red_recv_udp_pkt(fd, packet.dns.raw, sizeof(packet.dns.raw), &clientaddr, NULL);
	if (length <= (ssize_t)sizeof(dns_header))
		return;
	if ((packet.dns.hdr.qr_opcode_aa_tc_rd & DNS_QR) || !packet.dns.hdr.qdcount ||
	    packet.dns.hdr.ancount || packet.dns.hdr.nscount)
		return;
	inflight_req *req;
	list_for_each_entry(req, &self->requests, list) {
		// Preserve the original duplicate-ID behavior: clients retry collisions.
		if (req->id == packet.dns.hdr.id)
			return;
	}
	req = calloc(1, sizeof(*req));
	if (!req)
		return;
	if (!self->relay) {
		self->relay = red_connect_relay(&self->config.relayaddr,
			dnsu2t_relay_connected, dnsu2t_relay_error, self);
		if (!self->relay) {
			free(req);
			return;
		}
		bufferevent_settimeout(self->relay, self->config.relay_timeout, self->config.relay_timeout);
	}
	packet.sz = htons((uint16_t)length);
	if (bufferevent_write(self->relay, &packet, length + sizeof(packet.sz))) {
		free(req);
		dnsu2t_close_relay(self);
		return;
	}
	req->id = packet.dns.hdr.id;
	req->clientaddr = clientaddr;
	list_add_tail(&req->list, &self->requests);
	if (++self->inflight_count >= self->config.inflight_max && event_del(&self->listener))
		log_errno(LOG_ERR, "event_del");
}

/***********************************************************************
 * Init / shutdown
 */
static parser_entry dnsu2t_entries[] =
{
	{ .key = "local_ip",        .type = pt_in_addr },
	{ .key = "local_port",      .type = pt_uint16 },
	{ .key = "remote_ip",       .type = pt_in_addr },
	{ .key = "remote_port",     .type = pt_uint16 },
	{ .key = "remote_timeout",  .type = pt_uint16 },
	{ .key = "inflight_max",    .type = pt_uint16 },
	{ }
};

static list_head instances = LIST_HEAD_INIT(instances);

static int dnsu2t_onenter(parser_section *section)
{
	dnsu2t_instance *instance = calloc(1, sizeof(*instance));
	if (!instance) {
		parser_error(section->context, "Not enough memory");
		return -1;
	}

	INIT_LIST_HEAD(&instance->list);
	INIT_LIST_HEAD(&instance->requests);
	instance->config.bindaddr.sin_family = AF_INET;
	instance->config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	instance->config.bindaddr.sin_port = 53;
	instance->config.relayaddr.sin_family = AF_INET;
	instance->config.relayaddr.sin_port = 53;
	instance->config.relay_timeout = 30;
	instance->config.inflight_max = 16;

	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr =
			(strcmp(entry->key, "local_ip") == 0)   ? (void*)&instance->config.bindaddr.sin_addr :
			(strcmp(entry->key, "local_port") == 0) ? (void*)&instance->config.bindaddr.sin_port :
			(strcmp(entry->key, "remote_ip") == 0)  ? (void*)&instance->config.relayaddr.sin_addr :
			(strcmp(entry->key, "remote_port") == 0)? (void*)&instance->config.relayaddr.sin_port :
			(strcmp(entry->key, "remote_timeout") == 0)? (void*)&instance->config.relay_timeout:
			(strcmp(entry->key, "inflight_max") == 0)? (void*)&instance->config.inflight_max :
			NULL;
	section->data = instance;
	return 0;
}

static int dnsu2t_onexit(parser_section *section)
{
	dnsu2t_instance *instance = section->data;

	section->data = NULL;
	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr = NULL;

	instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);
	instance->config.relayaddr.sin_port = htons(instance->config.relayaddr.sin_port);

	if (!instance->config.inflight_max || !instance->config.relay_timeout) {
		parser_error(section->context, "inflight_max and remote_timeout must be positive");
		free(instance);
		return -1;
	}
	list_add(&instance->list, &instances);

	return 0;
}

static int dnsu2t_init_instance(dnsu2t_instance *instance)
{
	int error;
	int fd = red_socket_server(SOCK_DGRAM, &instance->config.bindaddr);

	if (fd == -1) {
		goto fail;
	}

	event_set(&instance->listener, fd, EV_READ | EV_PERSIST, dnsu2t_pkt_from_client, instance);
	fd = -1;
	error = event_add(&instance->listener, NULL);
	if (error) {
		log_errno(LOG_ERR, "event_add");
		goto fail;
	}

	return 0;

fail:
	dnsu2t_fini_instance(instance);

	if (fd != -1) {
		if (close(fd) != 0)
			log_errno(LOG_WARNING, "close");
	}

	return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void dnsu2t_fini_instance(dnsu2t_instance *instance)
{
	dnsu2t_close_relay(instance);

	if (event_initialized(&instance->listener)) {
		if (event_del(&instance->listener) != 0)
			log_errno(LOG_WARNING, "event_del");
		if (close(event_get_fd(&instance->listener)) != 0)
			log_errno(LOG_WARNING, "close");
		memset(&instance->listener, 0, sizeof(instance->listener));
	}

	list_del(&instance->list);

	memset(instance, 0, sizeof(*instance));
	free(instance);
}

static int dnsu2t_init()
{
	dnsu2t_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list) {
		if (dnsu2t_init_instance(instance) != 0)
			goto fail;
	}

	return 0;

fail:
	dnsu2t_fini();
	return -1;
}

static int dnsu2t_fini()
{
	dnsu2t_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list)
		dnsu2t_fini_instance(instance);

	return 0;
}

static parser_section dnsu2t_conf_section =
{
	.name    = "dnsu2t",
	.entries = dnsu2t_entries,
	.onenter = dnsu2t_onenter,
	.onexit  = dnsu2t_onexit
};

app_subsys dnsu2t_subsys =
{
	.init = dnsu2t_init,
	.fini = dnsu2t_fini,
	.conf_section = &dnsu2t_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
