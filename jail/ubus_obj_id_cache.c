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

#include "ubus_obj_id_cache.h"
#include "log.h"

#include <assert.h>
#include <libubus.h>

struct ubus_object_id
{
	struct avl_node avl;
	char path[0];
};

static int avl_uintptr_cmp(const void *k1, const void *k2, void *ptr)
{
	uintptr_t left = (uintptr_t)k1;
	uintptr_t right = (uintptr_t)k2;

	if (left < right)
		return -1;
	else
		return right < left;
}

static void avl_object_remove(struct ubus_obj_id_cache *server, uintptr_t id)
{
	struct ubus_object_id *node = avl_find_element(&server->avl, (void *)id, node, avl);
	if (node)
	{
		avl_delete(&server->avl, &node->avl);
		free(node);
	}
}

static void avl_object_add(struct ubus_obj_id_cache *server, uintptr_t id, const char *path)
{
	int path_len = strlen(path) + 1; // Include final NUL
	struct ubus_object_id *obj = calloc_a(sizeof(struct ubus_object_id) + path_len);

	memcpy(obj->path, path, path_len);

	// Check if node already exists
	avl_object_remove(server, id);

	obj->avl.key = (void *)(id);
	avl_insert(&server->avl, &obj->avl);
}

static void initial_object_list_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
	struct ubus_obj_id_cache *server = priv;
	avl_object_add(server, obj->id, obj->path);
	if (server->cb)
		server->cb(server, UBUS_OBJ_ID_CACHE_ADDED, obj->id, obj->path);
}

static void ubus_event_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
						const char *type, struct blob_attr *msg)
{
	struct ubus_obj_id_cache *server = container_of(ev, struct ubus_obj_id_cache, ev);
	static const struct blobmsg_policy policy[2] = {
		{"id", BLOBMSG_TYPE_INT32},
		{"path", BLOBMSG_TYPE_STRING},
	};
	struct blob_attr *attr[ARRAY_SIZE(policy)];

	bool is_add = false;
	bool is_remove = false;

	is_add = (strcmp(type, "ubus.object.add") == 0);
	if (!is_add)
		is_remove = (strcmp(type, "ubus.object.remove") == 0);

	if(!is_add && !is_remove)
		return;

	blobmsg_parse(policy, ARRAY_SIZE(policy), attr, blob_data(msg), blob_len(msg));
	if (!attr[0] || !attr[1])
		return;

	uint32_t id = blobmsg_get_u32(attr[0]);
	const char *path = blobmsg_get_string(attr[1]);

	if(is_add) {
		avl_object_add(server, id, path);
		if (server->cb)
			server->cb(server, UBUS_OBJ_ID_CACHE_ADDED, id, path);
	} else {
		avl_object_remove(server, id);
		if (server->cb)
			server->cb(server, UBUS_OBJ_ID_CACHE_REMOVED, id, path);
	}
}

void ubus_obj_id_cache_init(
	struct ubus_obj_id_cache *ctx,
	ubus_obj_id_cache_cb cb
) {
	// We depend on pointers being at least equal to a uint32_t since we're
	// using the pointer value inside the AVL tree as the actual value being
	// stored instead of pointing to an object.
	assert(sizeof(uint32_t) <= sizeof(uintptr_t));

	memset(ctx, 0, sizeof(*ctx));
	ctx->ubus = NULL;
	ctx->cb = cb;
	avl_init(&ctx->avl, avl_uintptr_cmp, false, NULL);
}

void ubus_obj_id_cache_ubus_connected(struct ubus_obj_id_cache *ctx, struct ubus_context *ubus)
{
	struct ubus_object_id *node, *tmp;
	ctx->ubus = ubus;

	/* Reset cache */
	avl_remove_all_elements(&ctx->avl, node, avl, tmp) {
		if (ctx->cb)
			ctx->cb(ctx, UBUS_OBJ_ID_CACHE_REMOVED, (uintptr_t)node->avl.key, node->path);
		free(node);
	}

	DEBUG("ID cache connected\n");

	/* Add a few permanent IDs into the list. */
	avl_object_add(ctx, 0, "(ubus core)");
	avl_object_add(ctx, UBUS_SYSTEM_OBJECT_EVENT, "(ubus event)");
	avl_object_add(ctx, UBUS_SYSTEM_OBJECT_ACL, "(ubus acl)");
	avl_object_add(ctx, UBUS_SYSTEM_OBJECT_MONITOR, "(ubus monitor)");

	ubus_register_event_handler(ubus, &ctx->ev, "ubus.object.*");
	ctx->ev.cb = ubus_event_cb;
	ubus_lookup(ubus, NULL, initial_object_list_cb, ctx);
}

void ubus_obj_id_cache_ubus_disconnected(struct ubus_obj_id_cache *ctx, struct ubus_context *ubus)
{
	struct ubus_object_id *node, *tmp;

	/* ubus_unregister_event_handler() would normally be potentially appropriate
	 * here, but it cannot (at the time of authorship) cope with ubus not
	 * being connected at the time of invocation, nor can it survive a
	 * reconnection cycle properly.
	 */
	memset(&ctx->ev, 0, sizeof(ctx->ev));

	/* Reset cache */
	avl_remove_all_elements(&ctx->avl, node, avl, tmp) {
		if (ctx->cb)
			ctx->cb(ctx, UBUS_OBJ_ID_CACHE_REMOVED, (uintptr_t)node->avl.key, node->path);
		free(node);
	}

}

void ubus_obj_id_cache_free(struct ubus_obj_id_cache *ctx)
{
	struct ubus_object_id *node, *tmp;

	ubus_unregister_event_handler(ctx->ubus, &ctx->ev);
	avl_remove_all_elements(&ctx->avl, node, avl, tmp) {
		free(node);
	}
}

const char *ubus_obj_id_cache_get(const struct ubus_obj_id_cache *server, uintptr_t id)
{
	struct ubus_object_id *node = avl_find_element(&server->avl, (void *)id, node, avl);
	if (!node)
		return NULL;

	return node->path;
}

