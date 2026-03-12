/*
 * Copyright (C) 2026 Tim Nordell <tnordell@airgain.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <syslog.h>
#include <linux/limits.h>

#include <libubox/blobmsg_json.h>
#include <libubox/usock.h>
#include <libubus.h>
#include <libubox/uloop.h>
#include <ubusmsg.h>

#include "ubus.h"
#include "ubus_obj_id_cache.h"
#include "log.h"

static const char UBUS_UNIX_SOCKET[] = "/var/run/ubus/ubus.sock";

struct ubus_relay_server {
	struct ubus_context ubus;
	struct uloop_timeout ubus_reconnect_tmo;
	struct uloop_fd fd;
	struct ubus_obj_id_cache id_cache;
	uint32_t session_obj_id;
};

struct ubus_forward_fd_ctx
{
	/* Structure watching for incoming data from ubus socket */
	struct uloop_fd fd;

	/* Holds ubus message header portion of an incoming message */
	struct ubus_msghdr msg_hdr;

	/* Holds the blob portion of an incoming message */
	struct blob_buf msg_data;

	/* If >=0, this contains a file descriptor passed via message */
	int msg_fd;

	/* How much data we've received so far */
	int rx_offset;

	/* How much data we've sent so far */
	int tx_offset;
};

struct ubus_forward_ctx
{
	struct ubus_relay_server *relay;
	struct ubus_forward_fd_ctx jail;
	struct ubus_forward_fd_ctx ubus;
};

static void ubus_cb(struct uloop_fd *sock, unsigned int events);
static void jail_cb(struct uloop_fd *sock, unsigned int events);
static bool msg_rx_cleanup(struct ubus_forward_fd_ctx *from);

static void ubus_forward_ctx_fd_init(struct ubus_forward_fd_ctx *ctx, int fd, uloop_fd_handler cb)
{
	blob_buf_init(&ctx->msg_data, 0);
	ctx->msg_fd = -1;
	ctx->fd.fd = fd;
	ctx->fd.cb = cb;
	uloop_fd_add(&ctx->fd, ULOOP_READ | ULOOP_ERROR_CB);
}

static void ubus_forward_ctx_fd_free(struct ubus_forward_fd_ctx *ctx)
{
	uloop_fd_delete(&ctx->fd);
	close(ctx->fd.fd);
	msg_rx_cleanup(ctx);
	blob_buf_free(&ctx->msg_data);
}

static struct ubus_forward_ctx *ubus_forward_ctx_new(int ubus_fd, int jail_fd, struct ubus_relay_server *relay)
{
	struct ubus_forward_ctx *ctx = calloc(1, sizeof(struct ubus_forward_ctx));

	ubus_forward_ctx_fd_init(&ctx->ubus, ubus_fd, ubus_cb);
	ubus_forward_ctx_fd_init(&ctx->jail, jail_fd, jail_cb);
	ctx->relay = relay;
	return ctx;
}

static void ubus_forward_ctx_free(struct ubus_forward_ctx *ctx)
{
	ubus_forward_ctx_fd_free(&ctx->jail);
	ubus_forward_ctx_fd_free(&ctx->ubus);
	free(ctx);
}

static void add_iov(struct iovec **i, int *offset, void *_base, size_t len)
{
	uint8_t *base = (uint8_t *)_base;
	if (*offset >= len) {
		*offset -= len;
		return;
	}

	len -= *offset;
	*offset = 0;

	(*i)->iov_base = base + *offset;
	(*i)->iov_len = len - *offset;
	(*i)++;
}

static bool msg_rx_header(struct ubus_forward_fd_ctx *from)
{
	// Note: The buffer must contain the same alignment as what struct cmsghdr
	// requires. Wrapping this in a union guarantees this. See "man cmsg".
	union {
		struct cmsghdr align;
		uint8_t buf[CMSG_SPACE(sizeof(int))];
	} u = {0};
	struct msghdr msghdr = { 0 };
	struct iovec iov[2] = {};
	int rc;

	struct iovec *i = iov;
	int offset = from->rx_offset;

	if(from->rx_offset >= sizeof(struct ubus_msghdr) + sizeof(struct blob_attr)) {
		return true;
	}

	// On the first byte of the incoming message, accept a file descriptor (if
	// sent) by the ubus daemon.
	if(from->rx_offset == 0) {
		blob_buf_init(&from->msg_data, 0);
		msghdr.msg_control = u.buf;
		msghdr.msg_controllen = sizeof(u.buf);
	}

	add_iov(&i, &offset, &from->msg_hdr, sizeof(struct ubus_msghdr));
	add_iov(&i, &offset, from->msg_data.head, sizeof(struct blob_attr));

	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = i - iov;

	// Pass along the message, which is mainly the ubus header, verbatim
	rc = recvmsg(from->fd.fd, &msghdr, 0);
	if(rc < 0)
		return false;

	from->rx_offset += rc;

	// Process auxiliary data. Note, depending on required padding based on
	// the platform, multiple file descriptors `could be returned even though a
	// well behaving ubus client only sends at most one in a given message. We
	// need to close the extra ones potentially received to not leak file
	// descriptors.
	if(msghdr.msg_control) {
		struct cmsghdr *cmsg;
		for (cmsg = CMSG_FIRSTHDR(&msghdr);
			cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msghdr, cmsg)
		) {
			if (cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_level == SOL_SOCKET) {
				int *fds = (int *)CMSG_DATA(cmsg);
				int fd_count = (cmsg->cmsg_len - sizeof(*cmsg)) / sizeof(int);
				for(int i = 0;i<fd_count;++i) {
					if(i == 0) {
						from->msg_fd = fds[i];
					} else {
						ERROR("ujail: Detected extra FD in ubus message\n");
						// Do not leak file descriptors from an attacker.
						close(fds[i]);
					}
				}
			}
		}
	}

	if (from->rx_offset != sizeof(struct ubus_msghdr) + sizeof(struct blob_attr))
		return false;

	int msg_size = blob_raw_len(from->msg_data.head);
	if(from->msg_data.buflen < msg_size) {
		int required = msg_size - from->msg_data.buflen;
		blob_buf_grow(&from->msg_data, required);
	}

	return true;
}

static bool msg_rx_body(struct ubus_forward_fd_ctx *from)
{
	if(from->rx_offset < sizeof(struct ubus_msghdr) + sizeof(struct blob_attr)) {
		return false;
	}

	int msg_size = blob_raw_len(from->msg_data.head);
	int offset = from->rx_offset - sizeof(struct ubus_msghdr);
	int remaining = msg_size - offset;
	if (remaining == 0)
		return true;

	uint8_t *data = (uint8_t *)(from->msg_data.head);
	int rc = read(from->fd.fd, data + offset, remaining);
	if(rc < 0)
		return false;

	from->rx_offset += rc;
	return remaining == rc;
}

static bool msg_rx(struct ubus_forward_fd_ctx *from)
{
	bool rc;

	rc = msg_rx_header(from);
	if (!rc)
		goto done;

	rc = msg_rx_body(from);
	if (!rc)
		goto done;

done:
	return rc;
}

static bool msg_tx(struct ubus_forward_fd_ctx *from, struct ubus_forward_fd_ctx *to)
{
	// This code is more or less from jail_cb in ubusd_main.c
	uint8_t fd_buf[CMSG_SPACE(sizeof(int))] = {0};
	struct msghdr msghdr = { 0 };
	struct iovec iov[2] = {};
	struct cmsghdr *cmsg;
	int rc;

	struct iovec *i = iov;
	int offset = from->tx_offset;

	add_iov(&i, &offset, &from->msg_hdr, sizeof(from->msg_hdr));
	add_iov(&i, &offset, from->msg_data.head, from->rx_offset - sizeof(from->msg_hdr));
	if (i == iov)
		return true;

	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = i - iov;

	if(from->msg_fd >= 0 && from->tx_offset == 0) {
		msghdr.msg_control = fd_buf;
		msghdr.msg_controllen = sizeof(fd_buf);

		cmsg = CMSG_FIRSTHDR(&msghdr);
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		*(int *) CMSG_DATA(cmsg) = from->msg_fd;
	}

	rc = sendmsg(to->fd.fd, &msghdr, 0);
	if (rc < 0)
		return false;

	from->tx_offset += rc;

	return from->tx_offset == from->rx_offset;
}

static void usock_relay(
	struct ubus_forward_ctx *client,
	struct ubus_forward_fd_ctx *from,
	struct ubus_forward_fd_ctx *to,
	unsigned int events)
{
	if (from->fd.error) {
		ubus_forward_ctx_free(client);
		return;
	}

	if ((events & ULOOP_READ) && msg_rx(from)) {
		// Attempt an early transmit here in case there's room.  If not,
		// we'll block off watching for more incoming data, and
		// start watching for our output pipe to be ready.
		if(msg_tx(from, to)) {
			msg_rx_cleanup(from);
		} else {
			// If we couldn't finish writing, monitor for being able to
			// transmit our message instead. (This only allows one message
			// in flight through the relay for a given direction.)
			from->fd.flags &= ~ULOOP_READ;
			to->fd.flags |= ULOOP_WRITE;
			uloop_fd_add(&from->fd, from->fd.flags);
			uloop_fd_add(&to->fd, to->fd.flags);
		}
	}

	// Note: from/to are flipped from the ULOOP_READ case - the buffer comes from
	//       the person who originally had ULOOP_READ set.
	if ((events & ULOOP_WRITE) && msg_tx(to, from)) {
		msg_rx_cleanup(to);

		// Re-enable watching for READs
		to->fd.flags |= ULOOP_READ;
		from->fd.flags &= ~ULOOP_WRITE;
		uloop_fd_add(&from->fd, from->fd.flags);
		uloop_fd_add(&to->fd, to->fd.flags);
	}
}

static bool msg_rx_cleanup(struct ubus_forward_fd_ctx *from)
{
	if(from->msg_fd >= 0) {
		close(from->msg_fd);
		from->msg_fd = -1;
	}
	from->rx_offset = 0;
	from->tx_offset = 0;
	return true;
}

static void jail_cb(struct uloop_fd *sock, unsigned int events)
{
	struct ubus_forward_fd_ctx *ctx_fd = container_of(sock, struct ubus_forward_fd_ctx, fd);
	struct ubus_forward_ctx *ctx = container_of(ctx_fd, struct ubus_forward_ctx, jail);
	usock_relay(ctx, &ctx->jail, &ctx->ubus, events);
}

static void ubus_cb(struct uloop_fd *sock, unsigned int events)
{
	struct ubus_forward_fd_ctx *ctx_fd = container_of(sock, struct ubus_forward_fd_ctx, fd);
	struct ubus_forward_ctx *ctx = container_of(ctx_fd, struct ubus_forward_ctx, ubus);

	usock_relay(ctx, &ctx->ubus, &ctx->jail, events);
}

static void ubus_relay_server_cb(struct uloop_fd *fd, unsigned int events)
{
	struct ubus_relay_server *server = container_of(fd, struct ubus_relay_server, fd);
	struct ubus_forward_ctx *ctx;
	int jail_fd, ubus_fd;
	struct ucred cred;

	jail_fd = accept(fd->fd, NULL, 0);
	if (jail_fd < 0) {
		return;
	}

	// Fetch peer PID/UID/GIO in order to pass it along
	unsigned int cred_len = sizeof(struct ucred);
	if (getsockopt(jail_fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == -1) {
		close(jail_fd);
		return;
	}

	ubus_fd = usock(USOCK_UNIX, UBUS_UNIX_SOCKET, NULL);
	if (ubus_fd < 0) {
		close(jail_fd);
		return;
	}

	ctx = ubus_forward_ctx_new(ubus_fd, jail_fd, server);
	if (!ctx) {
		close(jail_fd);
		close(ubus_fd);
		return;
	}

	return;
}

static void ubus_relay_ubus_disconnected(struct ubus_context *ctx) {
	struct ubus_relay_server *server = container_of(ctx, struct ubus_relay_server, ubus);

	INFO("Disconnected from ubus\n");
	uloop_fd_delete(&ctx->sock);
	uloop_timeout_set(&server->ubus_reconnect_tmo, 1000);
	ubus_obj_id_cache_ubus_disconnected(&server->id_cache, &server->ubus);
}

static void ubus_relay_ubus_connected(struct ubus_relay_server *server) {
	INFO("Reconnected to ubus\n");
	server->session_obj_id = 0;
	uloop_fd_add(&server->ubus.sock, ULOOP_BLOCKING | ULOOP_READ | ULOOP_ERROR_CB);
	ubus_obj_id_cache_ubus_connected(&server->id_cache, &server->ubus);
	server->ubus.connection_lost = ubus_relay_ubus_disconnected;
}

static void ubus_relay_ubus_timeout(struct uloop_timeout *ctx) {
	struct ubus_relay_server *server = container_of(ctx, struct ubus_relay_server, ubus_reconnect_tmo);
	if (ubus_connect_ctx(&server->ubus, NULL) == 0) {
		ubus_relay_ubus_connected(server);
	} else {
		uloop_timeout_set(&server->ubus_reconnect_tmo, 1000);
	}
}

static void ubus_relay_monitor_objs(
	struct ubus_obj_id_cache *cache,
	enum UBUS_OBJ_ID_CACHE method,
	uint32_t id,
	const char *path
) {
	struct ubus_relay_server *server = container_of(cache, struct ubus_relay_server, id_cache);
	if (strcmp(path, "session") == 0) {
		switch(method)
		{
			case UBUS_OBJ_ID_CACHE_ADDED:
				INFO("Session Object ID: %08x\n", id);
				server->session_obj_id = id;
				break;
			case UBUS_OBJ_ID_CACHE_REMOVED:
				INFO("Session Object is gone\n");
				server->session_obj_id = 0;
				break;
		}
	}
}

bool ubus_create_relay(pid_t pid)
{
	struct ubus_relay_server *server;
	char to[PATH_MAX];

	snprintf(to, sizeof(to), "/proc/%i/root/%s", pid, UBUS_UNIX_SOCKET);

	// Sanity check that the path isn't created yet in case the user
	// mounted the regular ubus socket in our filesystem.
	if (access(to, F_OK) == 0)
	{
		ERROR("\"%s\" exists already in container\n", UBUS_UNIX_SOCKET);
		return false;
	}

	mkdir_p(to, 0555);
	rmdir(to);

	umask(0111);

	server = calloc(1, sizeof(struct ubus_relay_server));
	server->fd.cb = ubus_relay_server_cb;
	server->fd.fd = usock(USOCK_UNIX | USOCK_SERVER | USOCK_NONBLOCK, to, NULL);
	if(server->fd.fd < 0) {
		ERROR("Unable to create ubus socket; errno=%i\n", errno);
		free(server);
		return false;
	}

	if (uloop_fd_add(&server->fd, ULOOP_READ) < 0) {
		ERROR("uloop_fd_add failed for ubus socket\n");
		free(server);
		return false;
	}

	ubus_obj_id_cache_init(&server->id_cache, ubus_relay_monitor_objs);

	/* Note: We'd use ubus_auto_connect(...) but it's currently broken
	* since the uloop_fd_add() call added doesn't pass in ULOOP_ERROR_CB.
	*/
	server->ubus.connection_lost = ubus_relay_ubus_disconnected;
	server->ubus_reconnect_tmo.cb = ubus_relay_ubus_timeout;
	uloop_timeout_set(&server->ubus_reconnect_tmo, 0);

	return true;
}
