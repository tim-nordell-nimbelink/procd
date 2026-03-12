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
#ifndef _JAIL_UBUS_H
#define _JAIL_UBUS_H

#include <sys/types.h>

struct ubus_context;
bool ubus_create_relay(pid_t pid);

#endif
