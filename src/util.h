/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Written by: Matthias Clasen <mclasen@redhat.com>
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <glib.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

void sys_log (DBusGMethodInvocation *context,
              const gchar           *format,
                                     ...);

gboolean spawn_with_login_uid (DBusGMethodInvocation  *context,
                               gchar                  *argv[],
                               GError                **error);

G_END_DECLS

#endif /* __UTIL_H__ */
