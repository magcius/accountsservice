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

#ifndef __ACCOUNTS_DAEMON_H__
#define __ACCOUNTS_DAEMON_H__

G_BEGIN_DECLS

#define TYPE_DAEMON (daemon_get_type ())
#define DAEMON(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_DAEMON, Daemon))
#define DAEMON_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), TYPE_DAEMON, DaemonClass))
#define IS_DAEMON(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_DAEMON))
#define IS_DAEMON_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_DAEMON))
#define DAEMON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_DAEMON, DaemonClass))

typedef struct DaemonClass DaemonClass;
typedef struct DaemonPrivate DaemonPrivate;

G_END_DECLS

#endif
