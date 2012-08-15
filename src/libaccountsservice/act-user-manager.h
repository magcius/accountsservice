/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2007 William Jon McCann <mccann@jhu.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef __ACT_USER_MANAGER_H__
#define __ACT_USER_MANAGER_H__

#include <glib-object.h>

#include "act-types.h"
#include "act-user-generated.h"

G_BEGIN_DECLS

#define ACT_TYPE_USER_MANAGER         (act_user_manager_get_type ())
#define ACT_USER_MANAGER(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), ACT_TYPE_USER_MANAGER, ActUserManager))
#define ACT_USER_MANAGER_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), ACT_TYPE_USER_MANAGER, ActUserManagerClass))
#define ACT_IS_USER_MANAGER(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), ACT_TYPE_USER_MANAGER))
#define ACT_IS_USER_MANAGER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), ACT_TYPE_USER_MANAGER))
#define ACT_USER_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), ACT_TYPE_USER_MANAGER, ActUserManagerClass))

typedef struct ActUserManagerPrivate ActUserManagerPrivate;
typedef struct ActUserManager ActUserManager;
typedef struct ActUserManagerClass ActUserManagerClass;

struct ActUserManager
{
        GObject                parent;
        ActUserManagerPrivate *priv;
};

struct ActUserManagerClass
{
        GObjectClass   parent_class;

        void          (* user_added)                (ActUserManager *user_manager,
                                                     ActUser        *user);
        void          (* user_removed)              (ActUserManager *user_manager,
                                                     ActUser        *user);
        void          (* user_is_logged_in_changed) (ActUserManager *user_manager,
                                                     ActUser        *user);
        void          (* user_changed)              (ActUserManager *user_manager,
                                                     ActUser        *user);
};

typedef enum ActUserManagerError
{
        ACT_USER_MANAGER_ERROR_GENERAL,
        ACT_USER_MANAGER_ERROR_KEY_NOT_FOUND
} ActUserManagerError;

#define ACT_USER_MANAGER_ERROR act_user_manager_error_quark ()

GQuark              act_user_manager_error_quark           (void);
GType               act_user_manager_get_type              (void);

ActUserManager *    act_user_manager_get_default           (void);

GSList *            act_user_manager_list_users            (ActUserManager *manager);
ActUser *           act_user_manager_get_user              (ActUserManager *manager,
                                                            const char     *username);

gboolean            act_user_manager_activate_user_session (ActUserManager *manager,
                                                            ActUser        *user);

gboolean            act_user_manager_can_switch            (ActUserManager *manager);

gboolean            act_user_manager_goto_login_session    (ActUserManager *manager);

ActUser *           act_user_manager_create_user           (ActUserManager     *manager,
                                                            const char         *username,
                                                            const char         *fullname,
                                                            ActUserAccountType  accounttype,
                                                            GError             **error);

ActUser *           act_user_manager_cache_user            (ActUserManager     *manager,
                                                            const char         *username,
                                                            GError            **error);
gboolean            act_user_manager_uncache_user          (ActUserManager     *manager,
                                                            const char         *username,
                                                            GError            **error);

gboolean            act_user_manager_delete_user           (ActUserManager     *manager,
                                                            ActUser            *user,
                                                            gboolean            remove_files,
                                                            GError             **error);


G_END_DECLS

#endif /* __ACT_USER_MANAGER_H__ */
