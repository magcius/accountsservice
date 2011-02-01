/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2004-2005 James M. Cape <jcape@ignore-your.tv>.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <config.h>

#include <float.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <dbus/dbus-glib.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <gio/gio.h>

#include "act-user-private.h"

#define ACT_USER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), ACT_TYPE_USER, ActUserClass))
#define ACT_IS_USER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), ACT_TYPE_USER))
#define ACT_USER_GET_CLASS(object) (G_TYPE_INSTANCE_GET_CLASS ((object), ACT_TYPE_USER, ActUserClass))

#define ACCOUNTS_NAME           "org.freedesktop.Accounts"
#define ACCOUNTS_USER_INTERFACE "org.freedesktop.Accounts.User"

enum {
        PROP_0,
        PROP_UID,
        PROP_USER_NAME,
        PROP_REAL_NAME,
        PROP_LOGIN_FREQUENCY,
        PROP_ICON_FILE,
        PROP_LANGUAGE,
        PROP_IS_LOADED
};

enum {
        CHANGED,
        SESSIONS_CHANGED,
        LAST_SIGNAL
};

struct _ActUser {
        GObject         parent;

        DBusGConnection *connection;
        DBusGProxy      *accounts_proxy;
        DBusGProxy      *object_proxy;
        DBusGProxyCall  *get_all_call;
        char            *object_path;

        uid_t           uid;
        char           *user_name;
        char           *real_name;
        char           *icon_file;
        char           *language;
        GList          *sessions;
        int             login_frequency;

        guint           is_loaded : 1;
};

struct _ActUserClass
{
        GObjectClass parent_class;
};

static void act_user_finalize     (GObject      *object);

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (ActUser, act_user, G_TYPE_OBJECT)

static int
session_compare (const char *a,
                 const char *b)
{
        if (a == NULL) {
                return 1;
        } else if (b == NULL) {
                return -1;
        }

        return strcmp (a, b);
}

void
_act_user_add_session (ActUser    *user,
                       const char *ssid)
{
        GList *li;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (ssid != NULL);

        li = g_list_find_custom (user->sessions, ssid, (GCompareFunc)session_compare);
        if (li == NULL) {
                g_debug ("ActUser: adding session %s", ssid);
                user->sessions = g_list_prepend (user->sessions, g_strdup (ssid));
                g_signal_emit (user, signals[SESSIONS_CHANGED], 0);
        } else {
                g_debug ("ActUser: session already present: %s", ssid);
        }
}

void
_act_user_remove_session (ActUser    *user,
                          const char *ssid)
{
        GList *li;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (ssid != NULL);

        li = g_list_find_custom (user->sessions, ssid, (GCompareFunc)session_compare);
        if (li != NULL) {
                g_debug ("ActUser: removing session %s", ssid);
                g_free (li->data);
                user->sessions = g_list_delete_link (user->sessions, li);
                g_signal_emit (user, signals[SESSIONS_CHANGED], 0);
        } else {
                g_debug ("ActUser: session not found: %s", ssid);
        }
}

guint
act_user_get_num_sessions (ActUser    *user)
{
        return g_list_length (user->sessions);
}

static void
act_user_set_property (GObject      *object,
                       guint         param_id,
                       const GValue *value,
                       GParamSpec   *pspec)
{
        ActUser *user;

        user = ACT_USER (object);

        switch (param_id) {
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
                break;
        }
}

static void
act_user_get_property (GObject    *object,
                       guint       param_id,
                       GValue     *value,
                       GParamSpec *pspec)
{
        ActUser *user;

        user = ACT_USER (object);

        switch (param_id) {
        case PROP_UID:
                g_value_set_int (value, user->uid);
                break;
        case PROP_USER_NAME:
                g_value_set_string (value, user->user_name);
                break;
        case PROP_REAL_NAME:
                g_value_set_string (value, user->real_name);
                break;
        case PROP_LOGIN_FREQUENCY:
                g_value_set_int (value, user->login_frequency);
                break;
        case PROP_ICON_FILE:
                g_value_set_string (value, user->icon_file);
                break;
        case PROP_LANGUAGE:
                g_value_set_string (value, user->language);
                break;
        case PROP_IS_LOADED:
                g_value_set_boolean (value, user->is_loaded);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
                break;
        }
}


static void
act_user_class_init (ActUserClass *class)
{
        GObjectClass *gobject_class;

        gobject_class = G_OBJECT_CLASS (class);

        gobject_class->finalize = act_user_finalize;
        gobject_class->set_property = act_user_set_property;
        gobject_class->get_property = act_user_get_property;

        g_object_class_install_property (gobject_class,
                                         PROP_REAL_NAME,
                                         g_param_spec_string ("real-name",
                                                              "Real Name",
                                                              "The real name to display for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));

        g_object_class_install_property (gobject_class,
                                         PROP_UID,
                                         g_param_spec_int ("uid",
                                                           "User ID",
                                                           "The UID for this user.",
                                                           0, G_MAXINT, 0,
                                                           G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_USER_NAME,
                                         g_param_spec_string ("user-name",
                                                              "User Name",
                                                              "The login name for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_LOGIN_FREQUENCY,
                                         g_param_spec_int ("login-frequency",
                                                           "login frequency",
                                                           "login frequency",
                                                           0,
                                                           G_MAXINT,
                                                           0,
                                                           G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_ICON_FILE,
                                         g_param_spec_string ("icon-file",
                                                              "Icon File",
                                                              "The path to an icon for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_LANGUAGE,
                                         g_param_spec_string ("language",
                                                              "Language",
                                                              "User's locale.",
                                                              NULL,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_IS_LOADED,
                                         g_param_spec_boolean ("is-loaded",
                                                               NULL,
                                                               NULL,
                                                               FALSE,
                                                               G_PARAM_READABLE));

        signals [CHANGED] =
                g_signal_new ("changed",
                              G_TYPE_FROM_CLASS (class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              g_cclosure_marshal_VOID__VOID,
                              G_TYPE_NONE, 0);
        signals [SESSIONS_CHANGED] =
                g_signal_new ("sessions-changed",
                              G_TYPE_FROM_CLASS (class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              g_cclosure_marshal_VOID__VOID,
                              G_TYPE_NONE, 0);
}

static void
act_user_init (ActUser *user)
{
        GError *error;

        user->user_name = NULL;
        user->real_name = NULL;
        user->sessions = NULL;

        error = NULL;
        user->connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (user->connection == NULL) {
                g_warning ("Couldn't connect to system bus: %s", error->message);
        }
}

static void
act_user_finalize (GObject *object)
{
        ActUser *user;

        user = ACT_USER (object);

        g_free (user->user_name);
        g_free (user->real_name);
        g_free (user->icon_file);
        g_free (user->language);
        g_free (user->object_path);

        if (user->accounts_proxy != NULL) {
                g_object_unref (user->accounts_proxy);
        }

        if (user->object_proxy != NULL) {
                g_object_unref (user->object_proxy);
        }

        if (user->connection != NULL) {
                dbus_g_connection_unref (user->connection);
        }

        if (G_OBJECT_CLASS (act_user_parent_class)->finalize)
                (*G_OBJECT_CLASS (act_user_parent_class)->finalize) (object);
}

static void
set_is_loaded (ActUser  *user,
               gboolean  is_loaded)
{
        if (user->is_loaded != is_loaded) {
                user->is_loaded = is_loaded;
                g_object_notify (G_OBJECT (user), "is-loaded");
        }
}

/**
 * act_user_get_uid:
 * @user: the user object to examine.
 *
 * Retrieves the ID of @user.
 *
 * Returns: (transfer none): a pointer to an array of characters which must not be modified or
 *  freed, or %NULL.
 **/

uid_t
act_user_get_uid (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), -1);

        return user->uid;
}

/**
 * act_user_get_real_name:
 * @user: the user object to examine.
 *
 * Retrieves the display name of @user.
 *
 * Returns: (transfer none): a pointer to an array of characters which must not be modified or
 *  freed, or %NULL.
 **/
const char *
act_user_get_real_name (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return (user->real_name ? user->real_name : user->user_name);
}

/**
 * act_user_get_user_name:
 * @user: the user object to examine.
 *
 * Retrieves the login name of @user.
 *
 * Returns: (transfer none): a pointer to an array of characters which must not be modified or
 *  freed, or %NULL.
 **/

const char *
act_user_get_user_name (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->user_name;
}

/**
 * act_user_get_login_frequency:
 * @user: a #ActUser
 *
 * Returns the number of times @user has logged in.
 *
 * Returns: the login frequency
 */
int
act_user_get_login_frequency (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), 0);

        return user->login_frequency;
}

int
act_user_collate (ActUser *user1,
                  ActUser *user2)
{
        const char *str1;
        const char *str2;
        int         num1;
        int         num2;
        guint       len1;
        guint       len2;

        g_return_val_if_fail (ACT_IS_USER (user1), 0);
        g_return_val_if_fail (ACT_IS_USER (user2), 0);

        num1 = user1->login_frequency;
        num2 = user2->login_frequency;

        if (num1 > num2) {
                return -1;
        }

        if (num1 < num2) {
                return 1;
        }


        len1 = g_list_length (user1->sessions);
        len2 = g_list_length (user2->sessions);

        if (len1 > len2) {
                return -1;
        }

        if (len1 < len2) {
                return 1;
        }

        /* if login frequency is equal try names */
        if (user1->real_name != NULL) {
                str1 = user1->real_name;
        } else {
                str1 = user1->user_name;
        }

        if (user2->real_name != NULL) {
                str2 = user2->real_name;
        } else {
                str2 = user2->user_name;
        }

        if (str1 == NULL && str2 != NULL) {
                return -1;
        }

        if (str1 != NULL && str2 == NULL) {
                return 1;
        }

        if (str1 == NULL && str2 == NULL) {
                return 0;
        }

        return g_utf8_collate (str1, str2);
}

/**
 * act_user_is_logged_in:
 * @user: a #ActUser
 *
 * Returns whether or not #ActUser is currently logged in.
 *
 * Returns: %TRUE or %FALSE
 */
gboolean
act_user_is_logged_in (ActUser *user)
{
        return user->sessions != NULL;
}

/**
 * act_user_get_icon_file:
 * @user: a #ActUser
 *
 * Returns the path to the account icon belonging to @user.
 *
 * Returns: (transfer none): a path to an icon
 */
const char *
act_user_get_icon_file (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->icon_file;
}

/**
 * act_user_get_language:
 * @user: a #ActUser
 *
 * Returns the path to the configured locale of @user.
 *
 * Returns: (transfer none): a path to an icon
 */
const char *
act_user_get_language (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->language;
}

/**
 * act_user_get_object_path:
 * @user: a #ActUser
 *
 * Returns the user accounts service object path of @user,
 * or %NULL if @user doesn't have an object path associated
 * with it.
 *
 * Returns: (transfer none): the primary ConsoleKit session id of the user
 */
const char *
act_user_get_object_path (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->object_path;
}

/**
 * act_user_get_primary_session_id:
 * @user: a #ActUser
 *
 * Returns the primary ConsoleKit session id of @user, or %NULL if @user isn't
 * logged in.
 *
 * Returns: (transfer none): the primary ConsoleKit session id of the user
 */
const char *
act_user_get_primary_session_id (ActUser *user)
{
        if (!act_user_is_logged_in (user)) {
                g_debug ("User %s is not logged in, so has no primary session",
                         act_user_get_user_name (user));
                return NULL;
        }

        /* FIXME: better way to choose? */
        return user->sessions->data;
}

static void
collect_props (const gchar    *key,
               const GValue   *value,
               ActUser        *user)
{
        gboolean handled = TRUE;

        if (strcmp (key, "Uid") == 0) {
                guint64 new_uid;

                new_uid = g_value_get_uint64 (value);
                if ((guint64) user->uid != new_uid) {
                        user->uid = (uid_t) new_uid;
                        g_object_notify (G_OBJECT (user), "uid");
                }
        } else if (strcmp (key, "UserName") == 0) {
                const char *new_user_name;

                new_user_name = g_value_get_string (value);
                if (g_strcmp0 (user->user_name, new_user_name) != 0) {
                        g_free (user->user_name);
                        user->user_name = g_strdup (new_user_name);
                        g_object_notify (G_OBJECT (user), "user-name");
                }
        } else if (strcmp (key, "RealName") == 0) {
                const char *new_real_name;

                new_real_name = g_value_get_string (value);
                if (g_strcmp0 (user->real_name, new_real_name) != 0) {
                        g_free (user->real_name);
                        user->real_name = g_strdup (new_real_name);
                        g_object_notify (G_OBJECT (user), "real-name");
                }
        } else if (strcmp (key, "LoginFrequency") == 0) {
                int new_login_frequency;

                new_login_frequency = g_value_get_int (value);
                if ((int) user->login_frequency != new_login_frequency) {
                        user->login_frequency = new_login_frequency;
                        g_object_notify (G_OBJECT (user), "login-frequency");
                }
        } else if (strcmp (key, "IconFile") == 0) {
                const char *new_icon_file;

                new_icon_file = g_value_get_string (value);
                if (g_strcmp0 (user->icon_file, new_icon_file) != 0) {
                        g_free (user->icon_file);
                        user->icon_file = g_value_dup_string (value);
                        g_object_notify (G_OBJECT (user), "icon-file");
                }
        } else if (strcmp (key, "Language") == 0) {
                const char *new_language;

                new_language = g_value_get_string (value);
                if (g_strcmp0 (user->language, new_language) != 0) {
                        g_free (user->language);
                        user->language = g_value_dup_string (value);
                        g_object_notify (G_OBJECT (user), "language");
                }
        } else {
                handled = FALSE;
        }

        if (!handled) {
                g_debug ("unhandled property %s", key);
        }
}

static void
on_get_all_finished (DBusGProxy     *proxy,
                     DBusGProxyCall *call,
                     ActUser        *user)
{
        GError      *error;
        GHashTable  *hash_table;
        gboolean     res;

        g_assert (user->get_all_call == call);
        g_assert (user->object_proxy == proxy);

        error = NULL;
        res = dbus_g_proxy_end_call (proxy,
                                     call,
                                     &error,
                                     dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
                                     &hash_table,
                                     G_TYPE_INVALID);
        user->get_all_call = NULL;
        user->object_proxy = NULL;

        if (! res) {
                g_debug ("Error calling GetAll() when retrieving properties for %s: %s",
                         user->object_path, error->message);
                g_error_free (error);
                goto out;
        }
        g_hash_table_foreach (hash_table, (GHFunc) collect_props, user);
        g_hash_table_unref (hash_table);

        if (!user->is_loaded) {
                set_is_loaded (user, TRUE);
        }

        g_signal_emit (user, signals[CHANGED], 0);

out:
        g_object_unref (proxy);
}

static gboolean
update_info (ActUser *user)
{
        DBusGProxy     *proxy;
        DBusGProxyCall *call;

        proxy = dbus_g_proxy_new_for_name (user->connection,
                                           ACCOUNTS_NAME,
                                           user->object_path,
                                           DBUS_INTERFACE_PROPERTIES);

        call = dbus_g_proxy_begin_call (proxy,
                                        "GetAll",
                                        (DBusGProxyCallNotify)
                                        on_get_all_finished,
                                        user,
                                        NULL,
                                        G_TYPE_STRING,
                                        ACCOUNTS_USER_INTERFACE,
                                        G_TYPE_INVALID);

        if (call == NULL) {
                g_warning ("ActUser: failed to make GetAll call");
                goto failed;
        }

        user->get_all_call = call;
        user->object_proxy = proxy;
        return TRUE;

failed:
        if (proxy != NULL) {
                g_object_unref (proxy);
        }

        return FALSE;
}

static void
changed_handler (DBusGProxy *proxy,
                 gpointer   *data)
{
        ActUser *user = ACT_USER (data);

        update_info (user);
}

/**
 * _act_user_update_from_object_path:
 * @user: the user object to update.
 * @object_path: the object path of the user to use.
 *
 * Updates the properties of @user from the accounts service via
 * the object path in @object_path.
 **/
void
_act_user_update_from_object_path (ActUser    *user,
                                   const char *object_path)
{
        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (object_path != NULL);
        g_return_if_fail (user->object_path == NULL);

        user->object_path = g_strdup (object_path);

        user->accounts_proxy = dbus_g_proxy_new_for_name (user->connection,
                                                          ACCOUNTS_NAME,
                                                          user->object_path,
                                                          ACCOUNTS_USER_INTERFACE);
        dbus_g_proxy_set_default_timeout (user->accounts_proxy, INT_MAX);
        dbus_g_proxy_add_signal (user->accounts_proxy, "Changed", G_TYPE_INVALID);

        dbus_g_proxy_connect_signal (user->accounts_proxy, "Changed",
                                     G_CALLBACK (changed_handler), user, NULL);

        if (!update_info (user)) {
                g_warning ("Couldn't update info for user with object path %s", object_path);
        }
}

void
_act_user_update_login_frequency (ActUser    *user,
                                  int         login_frequency)
{
        if (user->login_frequency != login_frequency) {
                user->login_frequency = login_frequency;
                g_object_notify (G_OBJECT (user), "login-frequency");
        }
}

/**
 * act_user_is_loaded:
 * @user: a #ActUser
 *
 * Determines whether or not the user object is loaded and ready to read from.
 * #ActUserManager:is-loaded property must be %TRUE before calling
 * act_user_manager_list_users()
 *
 * Returns: %TRUE or %FALSE
 */
gboolean
act_user_is_loaded (ActUser *user)
{
        return user->is_loaded;
}
