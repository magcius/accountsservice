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

#ifndef __DAEMON_H__
#define __DAEMON_H__

#include <sys/types.h>
#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>

#include "types.h"
#include "user.h"

G_BEGIN_DECLS

#define TYPE_DAEMON         (daemon_get_type ())
#define DAEMON(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_DAEMON, Daemon))
#define DAEMON_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), TYPE_DAEMON, DaemonClass))
#define IS_DAEMON(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_DAEMON))
#define IS_DAEMON_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_DAEMON))
#define DAEMON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_DAEMON, DaemonClass))

typedef struct DaemonClass DaemonClass;
typedef struct DaemonPrivate DaemonPrivate;

struct Daemon {
        GObject parent;
        DaemonPrivate *priv;
};

struct DaemonClass {
        GObjectClass parent_class;
};

typedef enum {
        ERROR_FAILED,
        ERROR_PERMISSION_DENIED,
        ERROR_NOT_SUPPORTED,
        NUM_ERRORS
} Error;

#define ERROR error_quark ()

GType error_get_type (void);
#define TYPE_ERROR (error_get_type ())
GQuark error_quark (void);

GType   daemon_get_type              (void) G_GNUC_CONST;
Daemon *daemon_new                   (void);

/* local methods */

User *daemon_local_find_user_by_id   (Daemon                *daemon,
                                      uid_t                  uid);
User *daemon_local_find_user_by_name (Daemon                *daemon,
                                      const gchar           *name);

typedef void (*AuthorizedCallback)   (Daemon                *daemon,
                                      User                  *user,
                                      DBusGMethodInvocation *context,
                                      gpointer               data);

void         daemon_local_check_auth (Daemon                *daemon,
                                      User                  *user,
                                      const gchar           *action_id,
                                      gboolean               allow_interaction,
                                      AuthorizedCallback     auth_cb,
                                      DBusGMethodInvocation *context,
                                      gpointer               data,
                                      GDestroyNotify         destroy_notify);

gboolean   daemon_local_set_automatic_login (Daemon         *daemon,
                                             User           *user,
                                             gboolean        enabled,
                                             GError        **error);

/* exported methods */

gboolean daemon_find_user_by_id   (Daemon                *daemon,
                                   gint64                 uid,
                                   DBusGMethodInvocation *context);
gboolean daemon_find_user_by_name (Daemon                *daemon,
                                   const gchar           *name,
                                   DBusGMethodInvocation *context);
gboolean daemon_list_cached_users (Daemon                *daemon,
                                   DBusGMethodInvocation *context);
gboolean daemon_create_user       (Daemon                *daemon,
                                   const gchar           *user_name,
                                   const gchar           *real_name,
                                   DBusGMethodInvocation *context);
gboolean daemon_delete_user       (Daemon                *daemon,
                                   gint64                 uid,
                                   gboolean               remove_files,
                                   DBusGMethodInvocation *context);

G_END_DECLS

#endif /* __DAEMON_H__ */
