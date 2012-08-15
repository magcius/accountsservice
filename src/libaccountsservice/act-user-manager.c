/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2007-2008 William Jon McCann <mccann@jhu.edu>
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

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif /* HAVE_PATHS_H */

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <glib/gstdio.h>
#include <glib-object.h>
#include <gio/gio.h>
#include <gio/gunixinputstream.h>

#include "act-user-manager.h"
#include "act-user-manager-generated.h"
#include "act-user-utils.h"

#define ACT_USER_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), ACT_TYPE_USER_MANAGER, ActUserManagerPrivate))

#define ACCOUNTS_NAME      "org.freedesktop.Accounts"
#define ACCOUNTS_PATH      "/org/freedesktop/Accounts"
#define ACCOUNTS_MANAGER_PATH ACCOUNTS_PATH "/Manager"
#define ACCOUNTS_INTERFACE "org.freedesktop.Accounts"

struct ActUserManagerPrivate
{
        GHashTable            *normal_users_by_name;
        GHashTable            *system_users_by_name;
        GDBusConnection       *connection;
        ActUserManagerGlue    *accounts_proxy;
        ActObjectManagerClient  *manager;

        GSList                *exclude_usernames;

        guint                  load_id;

        gboolean               has_multiple_users;
        gboolean               listing_cached_users;
};

enum {
        PROP_0,
        PROP_EXCLUDE_USERNAMES_LIST,
        PROP_IS_LOADED,
        PROP_HAS_MULTIPLE_USERS
};

enum {
        USER_ADDED,
        USER_REMOVED,
        USER_IS_LOGGED_IN_CHANGED,
        USER_CHANGED,
        LAST_SIGNAL
};

static guint signals [LAST_SIGNAL] = { 0, };

static void     act_user_manager_class_init (ActUserManagerClass *klass);
static void     act_user_manager_init       (ActUserManager      *user_manager);
static void     act_user_manager_finalize   (GObject             *object);

static gpointer user_manager_object = NULL;

G_DEFINE_TYPE (ActUserManager, act_user_manager, G_TYPE_OBJECT)

GQuark
act_user_manager_error_quark (void)
{
        static GQuark ret = 0;
        if (ret == 0) {
                ret = g_quark_from_static_string ("act_user_manager_error");
        }

        return ret;
}

static void
on_user_changed (ActUser        *user,
                 ActUserManager *manager)
{
        g_debug ("ActUserManager: user %s changed",
                 act_user_get_user_name (user));
        g_signal_emit (manager, signals[USER_CHANGED], 0, user);
}

static gint
match_name_cmpfunc (gconstpointer a,
                    gconstpointer b)
{
        return g_strcmp0 ((char *) a,
                          (char *) b);
}

static gboolean
username_in_exclude_list (ActUserManager *manager,
                          const char     *username)
{
        GSList   *found;
        gboolean  ret = FALSE;

        if (manager->priv->exclude_usernames != NULL) {
                found = g_slist_find_custom (manager->priv->exclude_usernames,
                                             username,
                                             match_name_cmpfunc);
                if (found != NULL) {
                        ret = TRUE;
                }
        }

        return ret;
}

static void
set_has_multiple_users (ActUserManager *manager,
                        gboolean        has_multiple_users)
{
        if (manager->priv->has_multiple_users != has_multiple_users) {
                manager->priv->has_multiple_users = has_multiple_users;
                g_object_notify (G_OBJECT (manager), "has-multiple-users");
        }
}

static void
add_user (ActUserManager *manager,
          ActUser        *user)
{
        g_debug ("ActUserManager: tracking user '%s'", act_user_get_user_name (user));
        if (act_user_get_system_account (user)) {
                g_hash_table_insert (manager->priv->system_users_by_name,
                                     g_strdup (act_user_get_user_name (user)),
                                     g_object_ref (user));
        } else {
                g_hash_table_insert (manager->priv->normal_users_by_name,
                                     g_strdup (act_user_get_user_name (user)),
                                     g_object_ref (user));
        }

        g_signal_connect_object (user,
                                 "changed",
                                 G_CALLBACK (on_user_changed),
                                 manager, 0);

        g_debug ("ActUserManager: loaded, so emitting user-added signal");
        g_signal_emit (manager, signals[USER_ADDED], 0, user);

        if (g_hash_table_size (manager->priv->normal_users_by_name) > 1) {
                set_has_multiple_users (manager, TRUE);
        }
}

static void
remove_user (ActUserManager *manager,
             ActUser        *user)
{
        const char *object_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (user));

        g_debug ("ActUserManager: no longer tracking user '%s' (with object path %s)",
                 act_user_get_user_name (user),
                 object_path);

        g_object_ref (user);

        g_signal_handlers_disconnect_by_func (user, on_user_changed, manager);
        if (act_user_get_user_name (user) != NULL) {
                g_hash_table_remove (manager->priv->normal_users_by_name, act_user_get_user_name (user));
                g_hash_table_remove (manager->priv->system_users_by_name, act_user_get_user_name (user));
        }

        g_debug ("ActUserManager: loaded, so emitting user-removed signal");
        g_signal_emit (manager, signals[USER_REMOVED], 0, user);

        g_object_unref (user);

        if (g_hash_table_size (manager->priv->normal_users_by_name) > 1) {
                set_has_multiple_users (manager, FALSE);
        }
}

static ActUser *
lookup_user_by_name (ActUserManager *manager,
                     const char     *username)
{
        ActUser *user;

        user = g_hash_table_lookup (manager->priv->normal_users_by_name, username);

        if (user == NULL) {
                user = g_hash_table_lookup (manager->priv->system_users_by_name, username);
        }

        return user;
}

static ActUser *
lookup_user_by_path (ActUserManager *manager,
                     const char     *object_path)
{
        GDBusObjectManager *objman;
        GDBusObject *obj;

        objman = G_DBUS_OBJECT_MANAGER (manager->priv->manager);
        obj = g_dbus_object_manager_get_object (objman, object_path);
        return act_object_peek_user (ACT_OBJECT (obj));
}

static void
try_associate_user (ActUserManager *manager,
                    ActUser        *user)
{
        const char *username;
        ActUser *old_user;

        username = act_user_get_user_name (user);

        if (username == NULL) {
                const char *object_path;

                object_path = g_dbus_proxy_get_object_path (G_DBUS_PROXY (user));

                g_warning ("ActUserManager: user has no username "
                           "(object path: %s, uid: %d)",
                           object_path, (int) act_user_get_uid (user));
                g_object_unref (user);
                return;
        }

        g_debug ("ActUserManager: user '%s' is now loaded", username);

        if (username_in_exclude_list (manager, username)) {
                g_debug ("ActUserManager: excluding user '%s'", username);
                g_object_unref (user);
                return;
        }

        old_user = lookup_user_by_name (manager, username);

        /* If username got added earlier by a different means, trump it now.
         */
        if (old_user != NULL) {
                g_debug ("ActUserManager: user '%s' was already known, "
                         "replacing with freshly loaded object", username);
                remove_user (manager, old_user);
        }

        add_user (manager, user);
        g_object_unref (user);
}

static void
on_object_added (GDBusObjectManager *objman,
                 GDBusObject        *object,
                 gpointer            user_data)
{
        ActUserManager *manager = user_data;
        ActUser *user = act_object_peek_user (ACT_OBJECT (object));
        try_associate_user (manager, user);
}

static void
on_object_removed (GDBusObjectManager *objman,
                   GDBusObject        *object,
                   gpointer            user_data)
{
        ActUserManager *manager = user_data;
        ActUser *user = act_object_peek_user (ACT_OBJECT (object));
        remove_user (manager, user);
}

/**
 * act_user_manager_get_user:
 * @manager: the manager to query.
 * @username: the login name of the user to get.
 *
 * Retrieves a pointer to the #ActUser object for the login @username
 * from @manager. Trying to use this object before its
 * #ActUser:is-loaded property is %TRUE will result in undefined
 * behavior.
 *
 * Returns: (transfer none): #ActUser object
 **/
ActUser *
act_user_manager_get_user (ActUserManager *manager,
                           const char     *username)
{
        ActUser *user;

        g_return_val_if_fail (ACT_IS_USER_MANAGER (manager), NULL);
        g_return_val_if_fail (username != NULL && username[0] != '\0', NULL);

        user = lookup_user_by_name (manager, username);

        /* if we don't have it loaded try to load it now */
        if (user == NULL) {
                char *path = NULL;
                GError *error = NULL;

                g_debug ("ActUserManager: trying to track new user with username %s", username);

                act_user_manager_glue_call_find_user_by_name_sync (manager->priv->accounts_proxy,
                                                                   username,
                                                                   &path,
                                                                   NULL,
                                                                   &error);

                if (error != NULL) {
                        g_warning ("Error while fetching user: %s\n", error->message);
                        g_error_free (error);
                } else {
                        user = lookup_user_by_path (manager, path);
                }
                g_free (path);
        }

        return user;
}

static void
listify_hash_values_hfunc (gpointer key,
                           gpointer value,
                           gpointer user_data)
{
        GSList **list = user_data;

        *list = g_slist_prepend (*list, value);
}

/**
 * act_user_manager_list_users:
 * @manager: a #ActUserManager
 *
 * Get a list of system user accounts
 *
 * Returns: (element-type ActUser) (transfer full): List of #ActUser objects
 */
GSList *
act_user_manager_list_users (ActUserManager *manager)
{
        GSList *retval;

        g_return_val_if_fail (ACT_IS_USER_MANAGER (manager), NULL);

        retval = NULL;
        g_hash_table_foreach (manager->priv->normal_users_by_name, listify_hash_values_hfunc, &retval);

        return g_slist_sort (retval, (GCompareFunc) act_user_collate);
}

static GSList *
slist_deep_copy (const GSList *list)
{
        GSList *retval;
        GSList *l;

        if (list == NULL)
                return NULL;

        retval = g_slist_copy ((GSList *) list);
        for (l = retval; l != NULL; l = l->next) {
                l->data = g_strdup (l->data);
        }

        return retval;
}

static void
act_user_manager_get_property (GObject        *object,
                               guint           prop_id,
                               GValue         *value,
                               GParamSpec     *pspec)
{
        ActUserManager *manager;

        manager = ACT_USER_MANAGER (object);

        switch (prop_id) {
        case PROP_HAS_MULTIPLE_USERS:
                g_value_set_boolean (value, manager->priv->has_multiple_users);
                break;
        case PROP_EXCLUDE_USERNAMES_LIST:
                g_value_set_pointer (value, manager->priv->exclude_usernames);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
set_exclude_usernames (ActUserManager *manager,
                       GSList         *list)
{
        if (manager->priv->exclude_usernames != NULL) {
                g_slist_foreach (manager->priv->exclude_usernames, (GFunc) g_free, NULL);
                g_slist_free (manager->priv->exclude_usernames);
        }
        manager->priv->exclude_usernames = slist_deep_copy (list);
}

static void
act_user_manager_set_property (GObject        *object,
                               guint           prop_id,
                               const GValue   *value,
                               GParamSpec     *pspec)
{
        ActUserManager *self;

        self = ACT_USER_MANAGER (object);

        switch (prop_id) {
        case PROP_EXCLUDE_USERNAMES_LIST:
                set_exclude_usernames (self, g_value_get_pointer (value));
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
act_user_manager_class_init (ActUserManagerClass *klass)
{
        GObjectClass   *object_class = G_OBJECT_CLASS (klass);

        object_class->finalize = act_user_manager_finalize;
        object_class->get_property = act_user_manager_get_property;
        object_class->set_property = act_user_manager_set_property;

        g_object_class_install_property (object_class,
                                         PROP_IS_LOADED,
                                         g_param_spec_boolean ("is-loaded",
                                                               NULL,
                                                               NULL,
                                                               FALSE,
                                                               G_PARAM_READABLE));
        g_object_class_install_property (object_class,
                                         PROP_HAS_MULTIPLE_USERS,
                                         g_param_spec_boolean ("has-multiple-users",
                                                               NULL,
                                                               NULL,
                                                               FALSE,
                                                               G_PARAM_READABLE));
        g_object_class_install_property (object_class,
                                         PROP_EXCLUDE_USERNAMES_LIST,
                                         g_param_spec_pointer ("exclude-usernames-list",
                                                               NULL,
                                                               NULL,
                                                               G_PARAM_READWRITE));

        signals [USER_ADDED] =
                g_signal_new ("user-added",
                              G_TYPE_FROM_CLASS (klass),
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (ActUserManagerClass, user_added),
                              NULL, NULL,
                              g_cclosure_marshal_VOID__OBJECT,
                              G_TYPE_NONE, 1, ACT_TYPE_USER);
        signals [USER_REMOVED] =
                g_signal_new ("user-removed",
                              G_TYPE_FROM_CLASS (klass),
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (ActUserManagerClass, user_removed),
                              NULL, NULL,
                              g_cclosure_marshal_VOID__OBJECT,
                              G_TYPE_NONE, 1, ACT_TYPE_USER);
        signals [USER_IS_LOGGED_IN_CHANGED] =
                g_signal_new ("user-is-logged-in-changed",
                              G_TYPE_FROM_CLASS (klass),
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (ActUserManagerClass, user_is_logged_in_changed),
                              NULL, NULL,
                              g_cclosure_marshal_VOID__OBJECT,
                              G_TYPE_NONE, 1, ACT_TYPE_USER);
        signals [USER_CHANGED] =
                g_signal_new ("user-changed",
                              G_TYPE_FROM_CLASS (klass),
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (ActUserManagerClass, user_changed),
                              NULL, NULL,
                              g_cclosure_marshal_VOID__OBJECT,
                              G_TYPE_NONE, 1, ACT_TYPE_USER);

        g_type_class_add_private (klass, sizeof (ActUserManagerPrivate));
}

static void
cache_users (ActUserManager *manager)
{
        GList *objects, *l;

        objects = g_dbus_object_manager_get_objects (G_DBUS_OBJECT_MANAGER (manager->priv->manager));
        for (l = objects; l != NULL; l = l->next) {
                ActObject *obj = ACT_OBJECT (l->data);
                ActUser *user;

                user = act_object_peek_user (obj);
                if (user == NULL) {
                        continue;
                }

                try_associate_user (manager, user);
        }
}

static void
act_user_manager_init (ActUserManager *manager)
{
        GError        *error;

        manager->priv = ACT_USER_MANAGER_GET_PRIVATE (manager);

        /* users */
        manager->priv->normal_users_by_name = g_hash_table_new_full (g_str_hash,
                                                                     g_str_equal,
                                                                     g_free,
                                                                     g_object_unref);
        manager->priv->system_users_by_name = g_hash_table_new_full (g_str_hash,
                                                                     g_str_equal,
                                                                     g_free,
                                                                     g_object_unref);

        error = NULL;
        manager->priv->connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
        if (manager->priv->connection == NULL) {
                if (error != NULL) {
                        g_warning ("Failed to connect to the D-Bus daemon: %s", error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Failed to connect to the D-Bus daemon");
                }
                return;
        }

        manager->priv->accounts_proxy = ACT_USER_MANAGER_GLUE (act_user_manager_glue_proxy_new_sync (manager->priv->connection,
                                                                                                     G_DBUS_PROXY_FLAGS_NONE,
                                                                                                     ACCOUNTS_NAME,
                                                                                                     ACCOUNTS_MANAGER_PATH,
                                                                                                     NULL,
                                                                                                     &error));
        if (manager->priv->accounts_proxy == NULL) {
                if (error != NULL) {
                        g_warning ("Failed to create accounts proxy: %s", error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Failed to create_accounts_proxy");
                }
                return;
        }
        g_dbus_proxy_set_default_timeout (G_DBUS_PROXY (manager->priv->accounts_proxy), G_MAXINT);

        manager->priv->manager = ACT_OBJECT_MANAGER_CLIENT (act_object_manager_client_new_sync (manager->priv->connection,
                                                                                                G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_NONE,
                                                                                                ACCOUNTS_NAME,
                                                                                                ACCOUNTS_PATH,
                                                                                                NULL,
                                                                                                &error));
        if (manager->priv->manager == NULL) {
                if (error != NULL) {
                        g_warning ("Failed to create manager: %s", error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Failed to create manager");
                }
                return;
        }

        g_signal_connect (manager->priv->manager,
                          "object-added",
                          G_CALLBACK (on_object_added),
                          manager);
        g_signal_connect (manager->priv->accounts_proxy,
                          "object-removed",
                          G_CALLBACK (on_object_removed),
                          manager);

        cache_users (manager);
}

static void
act_user_manager_finalize (GObject *object)
{
        ActUserManager *manager;

        g_return_if_fail (object != NULL);
        g_return_if_fail (ACT_IS_USER_MANAGER (object));

        manager = ACT_USER_MANAGER (object);

        g_return_if_fail (manager->priv != NULL);

        if (manager->priv->exclude_usernames != NULL) {
                g_slist_foreach (manager->priv->exclude_usernames, (GFunc) g_free, NULL);
                g_slist_free (manager->priv->exclude_usernames);
        }

        g_hash_table_destroy (manager->priv->normal_users_by_name);
        g_hash_table_destroy (manager->priv->system_users_by_name);

        G_OBJECT_CLASS (act_user_manager_parent_class)->finalize (object);
}

/**
 * act_user_manager_get_default:
 *
 * Returns the user manager singleton instance.  Calling this function will
 * automatically being loading the user list if it isn't loaded already.
 * The #ActUserManager:is-loaded property will be set to %TRUE when the users
 * are finished loading and then act_user_manager_list_users() can be called.
 *
 * Returns: (transfer none): user manager object
 */
ActUserManager *
act_user_manager_get_default (void)
{
        if (user_manager_object == NULL) {
                user_manager_object = g_object_new (ACT_TYPE_USER_MANAGER, NULL);
                g_object_add_weak_pointer (user_manager_object,
                                           (gpointer *) &user_manager_object);
        }

        return ACT_USER_MANAGER (user_manager_object);
}


/**
 * act_user_manager_create_user:
 * @manager: a #ActUserManager
 * @username: a unix user name
 * @fullname: a unix GECOS value
 * @accounttype: a #ActUserAccountType
 * @error: a #GError
 *
 * Creates a user account on the system.
 *
 * Returns: (transfer full): user object
 */
ActUser *
act_user_manager_create_user (ActUserManager      *manager,
                              const char          *username,
                              const char          *fullname,
                              ActUserAccountType   accounttype,
                              GError             **error)
{
        GError *local_error = NULL;
        gboolean res;
        gchar *path;
        ActUser *user;

        g_debug ("ActUserManager: Creating user '%s', '%s', %d",
                 username, fullname, accounttype);

        g_assert (manager->priv->accounts_proxy != NULL);

        local_error = NULL;
        res = act_user_manager_glue_call_create_user_sync (manager->priv->accounts_proxy,
                                                           username,
                                                           fullname,
                                                           accounttype,
                                                           &path,
                                                           NULL,
                                                           &local_error);
        if (! res) {
                g_propagate_error (error, local_error);
                return NULL;
        }

        user = lookup_user_by_path (manager, path);

        g_free (path);

        return user;
}

/**
 * act_user_manager_cache_user:
 * @manager: a #ActUserManager
 * @username: a user name
 * @error: a #GError
 *
 * Caches a user account so it shows up via act_user_manager_list_users().
 *
 * Returns: (transfer full): user object
 */
ActUser *
act_user_manager_cache_user (ActUserManager     *manager,
                             const char         *username,
                             GError            **error)
{
        GError *local_error = NULL;
        gboolean res;
        gchar *path;
        ActUser *user;

        g_debug ("ActUserManager: Caching user '%s'",
                 username);

        g_assert (manager->priv->accounts_proxy != NULL);

        local_error = NULL;
        res = act_user_manager_glue_call_cache_user_sync (manager->priv->accounts_proxy,
                                                          username,
                                                          &path,
                                                          NULL,
                                                          &local_error);
        if (! res) {
                g_propagate_error (error, local_error);
                return NULL;
        }

        user = lookup_user_by_path (manager, path);

        g_free (path);

        return user;
}

/**
 * act_user_manager_uncache_user:
 * @manager: a #ActUserManager
 * @username: a user name
 * @error: a #GError
 *
 * Releases all metadata about a user account, including icon,
 * language and session. If the user account is from a remote
 * server and the user has never logged in before, then that
 * account will no longer show up in ListCachedUsers() output.
 *
 * Returns: %TRUE if successful, otherwise %FALSE
 */
gboolean
act_user_manager_uncache_user (ActUserManager     *manager,
                               const char         *username,
                               GError            **error)
{
        GError *local_error = NULL;
        gboolean res;

        g_debug ("ActUserManager: Uncaching user '%s'",
                 username);

        g_assert (manager->priv->accounts_proxy != NULL);

        local_error = NULL;
        res = act_user_manager_glue_call_uncache_user_sync (manager->priv->accounts_proxy,
                                                            username,
                                                            NULL,
                                                            &local_error);
        if (! res) {
                g_propagate_error (error, local_error);
                return FALSE;
        }

        return TRUE;
}

gboolean
act_user_manager_delete_user (ActUserManager  *manager,
                              ActUser         *user,
                              gboolean         remove_files,
                              GError         **error)
{
        GError *local_error;
        gboolean res = TRUE;

        g_debug ("ActUserManager: Deleting user '%s' (uid %ld)", act_user_get_user_name (user), (long) act_user_get_uid (user));

        g_assert (manager->priv->accounts_proxy != NULL);

        local_error = NULL;
        if (!act_user_manager_glue_call_delete_user_sync (manager->priv->accounts_proxy,
                                                          act_user_get_uid (user),
                                                          remove_files,
                                                          NULL,
                                                          &local_error)) {
                g_propagate_error (error, local_error);
                res = FALSE;
        }

        return res;
}

