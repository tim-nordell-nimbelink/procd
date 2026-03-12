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
static const int TIMEOUT_FOR_ACCESS_CHECK_MS = 500;

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
	struct ubus_request acl_check;
	struct uloop_timeout acl_check_tmo;
	int pending_deny;
	const char *pending_deny_str;
	bool acl_blocked;
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

static void acl_check_data_cb(struct ubus_request *req, int type, struct blob_attr *msg);
static void acl_check_complete_cb(struct ubus_request *req, int ret);
static void acl_check_timeout_cb(struct uloop_timeout *tmo);

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
	ctx->acl_check.cancelled = true;
	ctx->acl_check_tmo.cb = acl_check_timeout_cb;
	ctx->pending_deny = -1;

	return ctx;
}

static void ubus_forward_ctx_free(struct ubus_forward_ctx *ctx)
{
	ubus_forward_ctx_fd_free(&ctx->jail);
	ubus_forward_ctx_fd_free(&ctx->ubus);
	if (!ctx->acl_check.cancelled)
		ubus_abort_request(&ctx->relay->ubus, &ctx->acl_check);
	if (ctx->acl_check_tmo.pending)
		uloop_timeout_cancel(&ctx->acl_check_tmo);
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

	if (from->rx_offset < sizeof(struct ubus_msghdr) + sizeof(struct blob_attr)) {
		return true;
	}

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

static const struct blob_attr_info ubus_policy[UBUS_ATTR_MAX] = {
	[UBUS_ATTR_STATUS] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_OBJPATH] = { .type = BLOB_ATTR_STRING },
	[UBUS_ATTR_OBJID] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_METHOD] = { .type = BLOB_ATTR_STRING },
	[UBUS_ATTR_OBJTYPE] = { .type = BLOB_ATTR_INT32 },
	[UBUS_ATTR_SIGNATURE] = { .type = BLOB_ATTR_NESTED },
	[UBUS_ATTR_DATA] = { .type = BLOB_ATTR_NESTED },
	[UBUS_ATTR_ACTIVE] = { .type = BLOB_ATTR_INT8 },
	[UBUS_ATTR_NO_REPLY] = { .type = BLOB_ATTR_INT8 },
	[UBUS_ATTR_USER] = { .type = BLOB_ATTR_STRING },
	[UBUS_ATTR_GROUP] = { .type = BLOB_ATTR_STRING },
};

static struct blob_buf b;

enum TX_STATE {
	TX_STATE_PUSH,
	TX_STATE_DEFERRED,
	TX_STATE_DROP,
};

static void acl_relay_block_print_info(struct ubus_forward_ctx *client, const char *reason)
{
	static const char * const msg_types[] = {
		[UBUS_MSG_HELLO] = "hello",
		[UBUS_MSG_STATUS] = "status",
		[UBUS_MSG_DATA] = "data",
		[UBUS_MSG_PING] = "ping",
		[UBUS_MSG_LOOKUP] = "lookup",
		[UBUS_MSG_INVOKE] = "invoke",
		[UBUS_MSG_ADD_OBJECT] = "add_object",
		[UBUS_MSG_REMOVE_OBJECT] = "remove_object",
		[UBUS_MSG_SUBSCRIBE] = "subscribe",
		[UBUS_MSG_UNSUBSCRIBE] = "unsubscribe",
		[UBUS_MSG_NOTIFY] = "notify",
	};

	struct blob_attr *attrbuf[UBUS_ATTR_MAX] = {};
	const char *type = "(unknown)";
	const char *path = NULL;
	const char *method = "(unset)";
	uint32_t remote_id;

	blob_parse_untrusted(
		client->jail.msg_data.head, client->jail.rx_offset - sizeof(struct ubus_msghdr),
		attrbuf, ubus_policy, UBUS_ATTR_MAX
	);

	if (client->jail.msg_hdr.type >= 0 && client->jail.msg_hdr.type < ARRAY_SIZE(msg_types)) {
		type = msg_types[client->jail.msg_hdr.type];
	}

	remote_id = be32_to_cpu(client->jail.msg_hdr.peer);
	path = ubus_obj_id_cache_get(&client->relay->id_cache, remote_id);
	if (!path)
		path = "(unknown)";
	if (attrbuf[UBUS_ATTR_METHOD])
		method = blob_get_string(attrbuf[UBUS_ATTR_METHOD]);

	fprintf(stderr, "(ujail) Blocking %s to object \"%s\" (%08x), method \"%s\"; %s\n", type, path, remote_id, method, reason);
}

static enum TX_STATE acl_check_pending_deny(struct ubus_forward_ctx *client) {
	if (client->pending_deny == -1) {
		return TX_STATE_PUSH;
	}

	// Check if we have an in-progress incoming message from ubus
	// (We need to wait for that to finish transmitting as we'll borrow
	// its buffers to send the actual rejection)
	if (client->ubus.rx_offset > 0)	{
		return TX_STATE_DEFERRED;
	}

	acl_relay_block_print_info(client, client->pending_deny_str);

	// Copy over the sequence from the incoming buffer and change type
	memcpy(&client->ubus.msg_hdr, &client->jail.msg_hdr, sizeof(struct ubus_msghdr));
	client->ubus.msg_hdr.type = UBUS_MSG_STATUS;

	// We're filling the ubus "receive" buffer, to reutilize the forward
	// mechanism from ubus -> jail
	blob_buf_init(&client->ubus.msg_data, 0);
	blob_put_int32(&client->ubus.msg_data, UBUS_ATTR_STATUS, client->pending_deny);

	// Set the rx_offset to match the full length
	client->ubus.rx_offset = sizeof(struct ubus_msghdr) + blob_raw_len(client->ubus.msg_data.head);
	client->ubus.tx_offset = 0;

	// Cleanup the receive context
	msg_rx_cleanup(&client->jail);
	client->jail.fd.flags |= ULOOP_WRITE;
	client->ubus.fd.flags &= ~ULOOP_READ;
	uloop_fd_add(&client->ubus.fd, client->ubus.fd.flags);
	uloop_fd_add(&client->jail.fd, client->jail.fd.flags);

	client->pending_deny = -1;

	return TX_STATE_DROP;
}

static enum TX_STATE acl_relay_block(struct ubus_forward_ctx *client, enum ubus_msg_status reason, const char *reason_str)
{
	client->pending_deny = reason;
	client->pending_deny_str = reason_str;

	return acl_check_pending_deny(client);
}

static enum TX_STATE ubus_relay_check_acl(struct ubus_forward_ctx *client)
{
	uint32_t remote_id = be32_to_cpu(client->jail.msg_hdr.peer);
	struct blob_attr *attr[UBUS_ATTR_MAX] = {};
	const char *path, *method;

	/* Note: uhttpd technically supports subscriptions, but there isn't a way
	 *       to provide the ubus_rpc_session ID when subscribing to something,
	 *       so let's just completely block these.
	 */
	if (client->jail.msg_hdr.type == UBUS_MSG_SUBSCRIBE) {
		return acl_relay_block(client, UBUS_STATUS_PERMISSION_DENIED, "drop all subscriptions");
	}

	/* Permit any non-invoke calls to go through */
	if (client->jail.msg_hdr.type != UBUS_MSG_INVOKE)
	{
		return TX_STATE_PUSH;
	}

	blob_parse_untrusted(
		client->jail.msg_data.head, client->jail.rx_offset - sizeof(struct ubus_msghdr),
		attr, ubus_policy, UBUS_ATTR_MAX
	);

	/* The target method and object ID must be present. */
	if (!attr[UBUS_ATTR_METHOD] || !attr[UBUS_ATTR_OBJID]) {
		return acl_relay_block(client, UBUS_STATUS_UNKNOWN_ERROR, "missing target method or object id");
	}

	if (blob_get_u32(attr[UBUS_ATTR_OBJID]) != remote_id)
	{
		return acl_relay_block(client, UBUS_STATUS_UNKNOWN_ERROR, "remote ID mismatch");
	}

	if (remote_id < UBUS_SYSTEM_OBJECT_MAX) {
		return acl_relay_block(client, UBUS_STATUS_PERMISSION_DENIED, "blocking call to system object");
	}

	path = ubus_obj_id_cache_get(&client->relay->id_cache, remote_id);
	method = blob_get_string(attr[UBUS_ATTR_METHOD]);

	if (!path) {
		return acl_relay_block(client, UBUS_STATUS_NOT_FOUND, "blocking call to unknown remote ID");
	}

	if (strcmp(path, "system") == 0 && strcmp(method, "board") == 0) {
		return TX_STATE_PUSH;
	}

	if (client->relay->session_obj_id == 0) {
		return acl_relay_block(client, UBUS_STATUS_UNKNOWN_ERROR, "blocking call because rpcd is not running");
	}

	/* uhttpd invokes the following objects without a session ID:
	 *
	 * 	session.get
	 * 	session.access
	 * 	session.destroy
	 * 	system.board
	 *
	 * We'll permit this subset.
	 */
	if (remote_id == client->relay->session_obj_id) {
		if (strcmp(method, "get") == 0) {
			return TX_STATE_PUSH;
		}
		if (strcmp(method, "access") == 0) {
			return TX_STATE_PUSH;
		}
		if (strcmp(method, "destroy") == 0) {
			return TX_STATE_PUSH;
		}
	}

	const char *ubus_rpc_session = "00000000000000000000000000000000";

	if (attr[UBUS_ATTR_DATA]) {
		static const struct blobmsg_policy session_attr[] = {
			{"ubus_rpc_session", BLOBMSG_TYPE_STRING},
		};
		struct blob_attr *session[ARRAY_SIZE(session_attr)] = {};

		/*
		 * Determine if ubus_rpc_session is set within the message. If it is,
		 * utilize that session, otherwise enforce the default session of
		 * "00000000000000000000000000000000".
		 */
		blobmsg_parse(session_attr, ARRAY_SIZE(session_attr), session, blob_data(attr[UBUS_ATTR_DATA]), blob_len(attr[UBUS_ATTR_DATA]));
		if (session[0]) {
			ubus_rpc_session = blobmsg_get_string(session[0]);
		}
	}

	/* Send out query to "ubus call session access" */
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "ubus_rpc_session", ubus_rpc_session);
	blobmsg_add_string(&b, "scope", "ubus");
	blobmsg_add_string(&b, "object", path);
	blobmsg_add_string(&b, "function", method);

	/* Give it an upper bound to respond; we don't want to block too long if rpcd
	 * isn't being responsive and would rather give a failure earlier.
	 */
	uloop_timeout_set(&client->acl_check_tmo, TIMEOUT_FOR_ACCESS_CHECK_MS);

	/* Setup the asynchronous invocation for the access check */
	ubus_invoke_async(&client->relay->ubus, client->relay->session_obj_id, "access", b.buf, &client->acl_check);
	client->acl_check.data_cb = acl_check_data_cb;
	client->acl_check.complete_cb = acl_check_complete_cb;
	ubus_complete_request_async(&client->relay->ubus, &client->acl_check);

	/* Set the default action from the async call to blocked */
	client->acl_blocked = true;

	return TX_STATE_DEFERRED;
}

static void acl_check_data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct ubus_forward_ctx *ctx = container_of(req, struct ubus_forward_ctx, acl_check);
	static const struct blobmsg_policy access_policy = {"access", BLOBMSG_TYPE_BOOL};
	struct blob_attr *access;

	blobmsg_parse(&access_policy, 1, &access, blob_data(msg), blob_len(msg));

	if(access && blobmsg_get_bool(access))
	{
		ctx->acl_blocked = false;
	}
}

static void acl_check_complete_cb(struct ubus_request *req, int ret)
{
	struct ubus_forward_ctx *ctx = container_of(req, struct ubus_forward_ctx, acl_check);

	if (ret == UBUS_STATUS_OK && !ctx->acl_blocked) {
		// Let the message pass through
		ctx->ubus.fd.flags |= ULOOP_WRITE;
		uloop_fd_add(&ctx->ubus.fd, ctx->ubus.fd.flags);
	} else {
		acl_relay_block(ctx, UBUS_STATUS_PERMISSION_DENIED, "rpcd denial");
	}

	uloop_timeout_cancel(&ctx->acl_check_tmo);
	ubus_complete_request_async(req->ctx, req);
}

static void acl_check_timeout_cb(struct uloop_timeout *t)
{
	struct ubus_forward_ctx *ctx = container_of(t, struct ubus_forward_ctx, acl_check_tmo);

	ubus_abort_request(&ctx->relay->ubus, &ctx->acl_check);
	acl_relay_block(ctx, UBUS_STATUS_UNKNOWN_ERROR, "rpcd ACL check timeout");
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
		enum TX_STATE should_tx = TX_STATE_PUSH;
		if (from == &client->jail)
			should_tx = ubus_relay_check_acl(client);

		switch(should_tx) {
			case TX_STATE_PUSH:
				// Attempt an early transmit here in case there's room. If not,
				// we'll block off watching for more incoming data, and
				// start watching for our output pipe to be ready.
				if(msg_tx(from, to)) {
					msg_rx_cleanup(from);
					acl_check_pending_deny(client);
				} else {
					// If we couldn't finish writing, monitor for being able to
					// transmit our message instead. (This only allows one message
					// in flight through the relay for a given direction.)
					from->fd.flags &= ~ULOOP_READ;
					to->fd.flags |= ULOOP_WRITE;
					uloop_fd_add(&from->fd, from->fd.flags);
					uloop_fd_add(&to->fd, to->fd.flags);
				}
				break;
			case TX_STATE_DROP:
				msg_rx_cleanup(from);
				break;
			case TX_STATE_DEFERRED:
				// Disable waiting for incoming data until we've resolved
				// if we can invoke this method.
				from->fd.flags &= ~ULOOP_READ;
				uloop_fd_add(&from->fd, from->fd.flags);
				break;
		}
	}

	// Note: from/to are flipped from the ULOOP_READ case - the buffer comes from
	//       the person who originally had ULOOP_READ set.
	if ((events & ULOOP_WRITE) && msg_tx(to, from)) {
		msg_rx_cleanup(to);
		acl_check_pending_deny(client);

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

	DEBUG("Disconnected from ubus\n");
	uloop_fd_delete(&ctx->sock);
	uloop_timeout_set(&server->ubus_reconnect_tmo, 1000);
	ubus_obj_id_cache_ubus_disconnected(&server->id_cache, &server->ubus);
}

static void ubus_relay_ubus_connected(struct ubus_relay_server *server) {
	DEBUG("Reconnected to ubus\n");
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
				DEBUG("Session Object ID: %08x\n", id);
				server->session_obj_id = id;
				break;
			case UBUS_OBJ_ID_CACHE_REMOVED:
				DEBUG("Session Object is gone\n");
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
