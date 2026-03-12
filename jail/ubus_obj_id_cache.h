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
#ifndef _JAIL_UBUS_OBJ_ID_CACHE_H
#define _JAIL_UBUS_OBJ_ID_CACHE_H

#include <libubox/avl.h>
#include <libubus.h>

enum UBUS_OBJ_ID_CACHE
{
  UBUS_OBJ_ID_CACHE_ADDED,
  UBUS_OBJ_ID_CACHE_REMOVED,
};

struct ubus_obj_id_cache;
typedef void (*ubus_obj_id_cache_cb)(struct ubus_obj_id_cache *, enum UBUS_OBJ_ID_CACHE, uint32_t id, const char *path);

struct ubus_obj_id_cache {
  struct ubus_context *ubus;
	struct ubus_event_handler ev;
	struct avl_tree avl;
  ubus_obj_id_cache_cb cb;
};

void ubus_obj_id_cache_init(struct ubus_obj_id_cache *cache, ubus_obj_id_cache_cb cb);
void ubus_obj_id_cache_ubus_connected(struct ubus_obj_id_cache *cache, struct ubus_context *ubus);
void ubus_obj_id_cache_ubus_disconnected(struct ubus_obj_id_cache *cache, struct ubus_context *ubus);
const char *ubus_obj_id_cache_get(const struct ubus_obj_id_cache *cache, uintptr_t id);
void ubus_obj_id_cache_free(struct ubus_obj_id_cache *cache);

#endif
