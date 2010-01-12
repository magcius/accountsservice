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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __USER__
#define __USER__

#include <sys/types.h>
#include <pwd.h>

#include <glib.h>
#include <dbus/dbus-glib.h>

#include "types.h"

G_BEGIN_DECLS

#define TYPE_USER (user_get_type ())
#define USER(object) (G_TYPE_CHECK_INSTANCE_CAST ((object), TYPE_USER, User))
#define IS_USER(object) (G_TYPE_CHECK_INSTANCE_TYPE ((object), TYPE_USER))

typedef enum {
        ACCOUNT_TYPE_STANDARD,
        ACCOUNT_TYPE_ADMINISTRATOR,
        ACCOUNT_TYPE_SUPERVISED,
#define ACCOUNT_TYPE_LAST ACCOUNT_TYPE_SUPERVISED
} AccountType;

typedef enum {
        PASSWORD_MODE_REGULAR,
        PASSWORD_MODE_SET_AT_LOGIN,
        PASSWORD_MODE_NONE,
#define PASSWORD_MODE_LAST PASSWORD_MODE_NONE
} PasswordMode;

/* local methods */

GType        user_get_type                  (void) G_GNUC_CONST;
User        *user_local_new                 (Daemon        *daemon,
                                             uid_t          uid);

void         user_local_update_from_pwent   (User          *user,
                                             struct passwd *pwent);
void         user_local_update_from_keyfile (User          *user,
                                             GKeyFile      *keyfile);

void         user_local_register            (User          *user);
void         user_local_unregister          (User          *user);

const gchar *user_local_get_user_name       (User          *user);
const gchar *user_local_get_object_path     (User          *user);

/* exported methods */

gboolean       user_set_user_name      (User                  *user,
                                        const gchar           *user_name,
                                        DBusGMethodInvocation *context);
gboolean       user_set_real_name      (User                  *user,
                                        const gchar           *real_name,
                                        DBusGMethodInvocation *context);
gboolean       user_set_email          (User                  *user,
                                        const gchar           *email,
                                        DBusGMethodInvocation *context);
gboolean       user_set_language       (User                  *user,
                                        const gchar           *language,
                                        DBusGMethodInvocation *context);
gboolean       user_set_location       (User                  *user,
                                        const gchar           *location,
                                        DBusGMethodInvocation *context);
gboolean       user_set_home_directory (User                  *user,
                                        const gchar           *home_dir,
                                        DBusGMethodInvocation *context);
gboolean       user_set_shell          (User                  *user,
                                        const gchar           *shell,
                                        DBusGMethodInvocation *context);
gboolean       user_set_icon_file      (User                  *user,
                                        const gchar           *filename,
                                        DBusGMethodInvocation *context);
gboolean       user_set_icon_data      (User                  *user,
                                        gint                   width,
                                        gint                   height,
                                        gint                   channels,
                                        gint                   rowstride,
                                        GArray                *data,
                                        DBusGMethodInvocation *context);
gboolean       user_set_locked         (User                  *user,
                                        gboolean               locked,
                                        DBusGMethodInvocation *context);
gboolean       user_set_account_type   (User                  *user,
                                        gint                   account_type,
                                        DBusGMethodInvocation *context);
gboolean       user_set_password_mode  (User                  *user,
                                        gint                   mode,
                                        DBusGMethodInvocation *context);
gboolean       user_set_password       (User                  *user,
                                        const gchar           *password,
                                        const gchar           *hint,
                                        DBusGMethodInvocation *context);

G_END_DECLS

#endif
