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

#include "act-user-manager.h"
#include "act-user-private.h"
#include "accounts-generated.h"
#include "ck-manager-generated.h"
#include "ck-seat-generated.h"
#include "ck-session-generated.h"

#define ACT_USER_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), ACT_TYPE_USER_MANAGER, ActUserManagerPrivate))

#define CK_NAME      "org.freedesktop.ConsoleKit"

#define CK_MANAGER_PATH      "/org/freedesktop/ConsoleKit/Manager"
#define CK_MANAGER_INTERFACE "org.freedesktop.ConsoleKit.Manager"
#define CK_SEAT_INTERFACE    "org.freedesktop.ConsoleKit.Seat"
#define CK_SESSION_INTERFACE "org.freedesktop.ConsoleKit.Session"

#define ACCOUNTS_NAME      "org.freedesktop.Accounts"
#define ACCOUNTS_PATH      "/org/freedesktop/Accounts"
#define ACCOUNTS_INTERFACE "org.freedesktop.Accounts"

typedef enum {
        ACT_USER_MANAGER_SEAT_STATE_UNLOADED = 0,
        ACT_USER_MANAGER_SEAT_STATE_GET_SESSION_ID,
        ACT_USER_MANAGER_SEAT_STATE_GET_SESSION_PROXY,
        ACT_USER_MANAGER_SEAT_STATE_GET_ID,
        ACT_USER_MANAGER_SEAT_STATE_GET_SEAT_PROXY,
        ACT_USER_MANAGER_SEAT_STATE_LOADED,
} ActUserManagerSeatState;

typedef struct
{
        ActUserManagerSeatState      state;
        char                        *id;
        char                        *session_id;
        ConsoleKitSeat              *seat_proxy;
        ConsoleKitSession           *session_proxy;
} ActUserManagerSeat;

typedef enum {
        ACT_USER_MANAGER_NEW_SESSION_STATE_UNLOADED = 0,
        ACT_USER_MANAGER_NEW_SESSION_STATE_GET_PROXY,
        ACT_USER_MANAGER_NEW_SESSION_STATE_GET_UID,
        ACT_USER_MANAGER_NEW_SESSION_STATE_GET_X11_DISPLAY,
        ACT_USER_MANAGER_NEW_SESSION_STATE_MAYBE_ADD,
        ACT_USER_MANAGER_NEW_SESSION_STATE_LOADED,
} ActUserManagerNewSessionState;

typedef struct
{
        ActUserManager                  *manager;
        ActUserManagerNewSessionState    state;
        char                            *id;
        ConsoleKitSession               *proxy;
        uid_t                            uid;
        char                            *x11_display;
} ActUserManagerNewSession;

typedef enum {
        ACT_USER_MANAGER_GET_USER_STATE_UNFETCHED = 0,
        ACT_USER_MANAGER_GET_USER_STATE_WAIT_FOR_LOADED,
        ACT_USER_MANAGER_GET_USER_STATE_ASK_ACCOUNTS_SERVICE,
        ACT_USER_MANAGER_GET_USER_STATE_FETCHED
} ActUserManagerGetUserState;

typedef struct
{
        ActUserManager             *manager;
        ActUserManagerGetUserState  state;
        ActUser                    *user;
        char                       *username;
        char                       *object_path;
} ActUserManagerFetchUserRequest;

struct ActUserManagerPrivate
{
        GHashTable            *users_by_name;
        GHashTable            *users_by_object_path;
        GHashTable            *sessions;
        GDBusConnection       *connection;
        AccountsAccounts      *accounts_proxy;
        ConsoleKitManager     *ck_manager_proxy;

        ActUserManagerSeat     seat;

        GSList                *new_sessions;
        GSList                *new_users;
        GSList                *new_users_inhibiting_load;
        GSList                *fetch_user_requests;

        GSList                *exclude_usernames;
        GSList                *include_usernames;

        guint                  load_id;

        gboolean               is_loaded;
        gboolean               has_multiple_users;
        gboolean               getting_sessions;
        gboolean               listing_cached_users;
};

enum {
        PROP_0,
        PROP_INCLUDE_USERNAMES_LIST,
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

static void     load_seat_incrementally     (ActUserManager *manager);
static void     unload_seat                 (ActUserManager *manager);
static void     load_users                  (ActUserManager *manager);
static void     act_user_manager_queue_load (ActUserManager *manager);
static void     queue_load_seat_and_users   (ActUserManager *manager);

static void     load_new_session_incrementally (ActUserManagerNewSession *new_session);
static void     set_is_loaded (ActUserManager *manager, gboolean is_loaded);

static void     on_new_user_loaded (ActUser        *user,
                                    GParamSpec     *pspec,
                                    ActUserManager *manager);
static void     give_up (ActUserManager                 *manager,
                         ActUserManagerFetchUserRequest *request);
static void     fetch_user_incrementally       (ActUserManagerFetchUserRequest *request);

static void     maybe_set_is_loaded            (ActUserManager *manager);
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

static gboolean
start_new_login_session (ActUserManager *manager)
{
        GError  *error;
        gboolean res;

        res = g_spawn_command_line_async ("gdmflexiserver -s", &error);
        if (! res) {
                if (error != NULL) {
                        g_warning ("Unable to start new login: %s", error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Unable to start new login");
                }
        }

        return res;
}

static gboolean
activate_session_id (ActUserManager *manager,
                     const char     *seat_id,
                     const char     *session_id)
{
        ConsoleKitSeat *proxy;
        GError         *error = NULL;
        gboolean        res = FALSE;
  
        proxy = console_kit_seat_proxy_new_sync (manager->priv->connection,
                                                 G_DBUS_PROXY_FLAGS_NONE,
                                                 CK_NAME,
                                                 seat_id,
                                                 NULL,
                                                 &error);
        if (proxy)
                res = console_kit_seat_call_activate_session_sync (proxy,
                                                                   session_id,
                                                                   NULL,
                                                                   &error);

        if (!res) {
                g_warning ("Unable to activate session: %s", error->message);
                g_error_free (error);
                return FALSE;
        }

        return TRUE;
}

static gboolean
session_is_login_window (ActUserManager *manager,
                         const char     *session_id)
{
        ConsoleKitSession *proxy;
        GError            *error = NULL;
        char              *session_type;
        gboolean           res = FALSE;
        gboolean           ret;

        proxy = console_kit_session_proxy_new_sync (manager->priv->connection,
                                                    G_DBUS_PROXY_FLAGS_NONE,
                                                    CK_NAME,
                                                    session_id,
                                                    NULL,
                                                    &error);
        if (proxy)
                res = console_kit_session_call_get_session_type_sync (proxy, &session_type, NULL, &error);

        if (!res) {
                if (error != NULL) {
                        g_debug ("ActUserManager: Failed to identify the session type: %s", error->message);
                        g_error_free (error);
                } else {
                        g_debug ("ActUserManager: Failed to identify the session type");
                }
                return FALSE;
        }
        if (proxy)
                g_object_unref (proxy);

        ret = strcmp (session_type, "LoginWindow") == 0;
        g_free (session_type);

        return ret;
}

static char *
_get_login_window_session_id (ActUserManager *manager)
{
        gboolean    can_activate_sessions;
        GError     *error = NULL;
        gchar     **sessions, **i;
        char       *primary_ssid;

        if (manager->priv->seat.id == NULL || manager->priv->seat.id[0] == '\0') {
                g_debug ("ActUserManager: display seat ID is not set; can't switch sessions");
                return NULL;
        }

        can_activate_sessions = act_user_manager_can_switch (manager);

        if (! can_activate_sessions) {
                g_debug ("ActUserManager: seat is unable to activate sessions");
                return NULL;
        }

        if (!console_kit_seat_call_get_sessions_sync (manager->priv->seat.seat_proxy, &sessions, NULL, &error)) {
                if (error != NULL) {
                        g_warning ("unable to determine sessions for user: %s",
                                   error->message);
                        g_error_free (error);
                } else {
                        g_warning ("unable to determine sessions for user");
                }
                return NULL;
        }

        primary_ssid = NULL;
        for (i = sessions; i; i++) {
                if (session_is_login_window (manager, *i)) {
                        primary_ssid = g_strdup (*i);
                        break;
                }
        }
        g_strfreev (sessions);

        return primary_ssid;
}

gboolean
act_user_manager_goto_login_session (ActUserManager *manager)
{
        gboolean ret;
        gboolean res;
        char    *ssid;

        g_return_val_if_fail (ACT_IS_USER_MANAGER (manager), FALSE);
        g_return_val_if_fail (manager->priv->is_loaded, FALSE);

        ret = FALSE;

        /* First look for any existing LoginWindow sessions on the seat.
           If none are found, create a new one. */

        ssid = _get_login_window_session_id (manager);
        if (ssid != NULL) {
                res = activate_session_id (manager, manager->priv->seat.id, ssid);
                if (res) {
                        ret = TRUE;
                }
        }

        if (! ret) {
                res = start_new_login_session (manager);
                if (res) {
                        ret = TRUE;
                }
        }

        return ret;
}

gboolean
act_user_manager_can_switch (ActUserManager *manager)
{
        gboolean  can_activate_sessions;
        GError   *error = NULL;

        if (!manager->priv->is_loaded) {
                g_debug ("ActUserManager: Unable to switch sessions until fully loaded");
                return FALSE;
        }

        if (manager->priv->seat.id == NULL || manager->priv->seat.id[0] == '\0') {
                g_debug ("ActUserManager: display seat ID is not set; can't switch sessions");
                return FALSE;
        }

        g_debug ("ActUserManager: checking if seat can activate sessions");

        if (!console_kit_seat_call_can_activate_sessions_sync (manager->priv->seat.seat_proxy, &can_activate_sessions, NULL, &error)) {
                if (error != NULL) {
                        g_warning ("unable to determine if seat can activate sessions: %s",
                                   error->message);
                        g_error_free (error);
                } else {
                        g_warning ("unable to determine if seat can activate sessions");
                }
                return FALSE;
        }

        return can_activate_sessions;
}

gboolean
act_user_manager_activate_user_session (ActUserManager *manager,
                                        ActUser        *user)
{
        gboolean ret;
        const char *ssid;
        gboolean res;

        gboolean can_activate_sessions;
        g_return_val_if_fail (ACT_IS_USER_MANAGER (manager), FALSE);
        g_return_val_if_fail (ACT_IS_USER (user), FALSE);
        g_return_val_if_fail (manager->priv->is_loaded, FALSE);

        ret = FALSE;

        can_activate_sessions = act_user_manager_can_switch (manager);

        if (! can_activate_sessions) {
                g_debug ("ActUserManager: seat is unable to activate sessions");
                goto out;
        }

        ssid = act_user_get_primary_session_id (user);
        if (ssid == NULL) {
                goto out;
        }

        res = activate_session_id (manager, manager->priv->seat.id, ssid);
        if (! res) {
                g_debug ("ActUserManager: unable to activate session: %s", ssid);
                goto out;
        }

        ret = TRUE;
 out:
        return ret;
}

static void
on_user_sessions_changed (ActUser        *user,
                          ActUserManager *manager)
{
        guint nsessions;

        if (! manager->priv->is_loaded) {
                return;
        }

        nsessions = act_user_get_num_sessions (user);

        g_debug ("ActUserManager: sessions changed user=%s num=%d",
                 act_user_get_user_name (user),
                 nsessions);

        /* only signal on zero and one */
        if (nsessions > 1) {
                return;
        }

        g_signal_emit (manager, signals [USER_IS_LOGGED_IN_CHANGED], 0, user);
}

static void
on_user_changed (ActUser        *user,
                 ActUserManager *manager)
{
        if (manager->priv->is_loaded) {
                g_debug ("ActUserManager: user %s changed",
                         act_user_get_user_name (user));
                g_signal_emit (manager, signals[USER_CHANGED], 0, user);
        }
}

static void
on_get_seat_id_finished (GObject        *object,
                         GAsyncResult   *result,
                         gpointer        data)
{
        ConsoleKitSession *proxy = CONSOLE_KIT_SESSION (object);
        ActUserManager    *manager = data;
        GError            *error = NULL;
        char              *seat_id;

        if (!console_kit_session_call_get_seat_id_finish (proxy, &seat_id, result, &error)) {
                if (error != NULL) {
                        g_debug ("Failed to identify the seat of the "
                                 "current session: %s",
                                 error->message);
                        g_error_free (error);
                } else {
                        g_debug ("Failed to identify the seat of the "
                                 "current session");
                }

                g_debug ("ActUserManager: GetSeatId call failed, so unloading seat");
                unload_seat (manager);
                return;
        }

        g_debug ("ActUserManager: Found current seat: %s", seat_id);

        manager->priv->seat.id = seat_id;
        manager->priv->seat.state++;

        load_seat_incrementally (manager);
}

static void
get_seat_id_for_current_session (ActUserManager *manager)
{
        console_kit_session_call_get_seat_id (manager->priv->seat.session_proxy,
                                              NULL,
                                              on_get_seat_id_finished,
                                              manager);
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
add_session_for_user (ActUserManager *manager,
                      ActUser        *user,
                      const char     *ssid)
{
        g_hash_table_insert (manager->priv->sessions,
                             g_strdup (ssid),
                             g_strdup (act_user_get_user_name (user)));

        _act_user_add_session (user, ssid);
        g_debug ("ActUserManager: added session for user: %s", act_user_get_user_name (user));
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

static ActUser *
create_new_user (ActUserManager *manager)
{
        ActUser *user;

        user = g_object_new (ACT_TYPE_USER, NULL);

        manager->priv->new_users = g_slist_prepend (manager->priv->new_users, user);

        g_signal_connect (user, "notify::is-loaded", G_CALLBACK (on_new_user_loaded), manager);

        return g_object_ref (user);
}

static void
add_user (ActUserManager *manager,
          ActUser        *user)
{
        const char *object_path;

        g_debug ("ActUserManager: tracking user '%s'", act_user_get_user_name (user));
        g_hash_table_insert (manager->priv->users_by_name,
                             g_strdup (act_user_get_user_name (user)),
                             g_object_ref (user));

        object_path = act_user_get_object_path (user);
        if (object_path != NULL) {
                g_hash_table_insert (manager->priv->users_by_object_path,
                                     (gpointer) object_path,
                                     g_object_ref (user));
        }

        g_signal_connect (user,
                          "sessions-changed",
                          G_CALLBACK (on_user_sessions_changed),
                          manager);
        g_signal_connect (user,
                          "changed",
                          G_CALLBACK (on_user_changed),
                          manager);

        if (manager->priv->is_loaded) {
                g_debug ("ActUserManager: loaded, so emitting user-added signal");
                g_signal_emit (manager, signals[USER_ADDED], 0, user);
        } else {
                g_debug ("ActUserManager: not yet loaded, so not emitting user-added signal");
        }

        if (g_hash_table_size (manager->priv->users_by_name) > 1) {
                set_has_multiple_users (manager, TRUE);
        }
}

static void
remove_user (ActUserManager *manager,
             ActUser        *user)
{
        g_debug ("ActUserManager: no longer tracking user '%s' (with object path %s)",
                 act_user_get_user_name (user),
                 act_user_get_object_path (user));

        g_object_ref (user);

        g_signal_handlers_disconnect_by_func (user, on_user_changed, manager);
        g_signal_handlers_disconnect_by_func (user, on_user_sessions_changed, manager);
        if (act_user_get_object_path (user) != NULL) {
                g_hash_table_remove (manager->priv->users_by_object_path, act_user_get_object_path (user));
        }
        if (act_user_get_user_name (user) != NULL) {
                g_hash_table_remove (manager->priv->users_by_name, act_user_get_user_name (user));

        }

        if (manager->priv->is_loaded) {
                g_debug ("ActUserManager: loaded, so emitting user-removed signal");
                g_signal_emit (manager, signals[USER_REMOVED], 0, user);
        } else {
                g_debug ("ActUserManager: not yet loaded, so not emitting user-removed signal");
        }

        g_object_unref (user);

        if (g_hash_table_size (manager->priv->users_by_name) > 1) {
                set_has_multiple_users (manager, FALSE);
        }
}

static void
on_new_user_loaded (ActUser        *user,
                    GParamSpec     *pspec,
                    ActUserManager *manager)
{
        const char *username;
        ActUser *old_user;

        if (!act_user_is_loaded (user)) {
                g_debug ("ActUserManager: user '%s' loaded function called when not loaded",
                         act_user_get_user_name (user));
                return;
        }
        g_signal_handlers_disconnect_by_func (user, on_new_user_loaded, manager);

        manager->priv->new_users = g_slist_remove (manager->priv->new_users,
                                                   user);
        manager->priv->new_users_inhibiting_load = g_slist_remove (manager->priv->new_users_inhibiting_load,
                                                                   user);

        username = act_user_get_user_name (user);

        if (username == NULL) {
                const char *object_path;

                object_path = act_user_get_object_path (user);

                if (object_path != NULL) {
                        g_warning ("ActUserManager: user has no username "
                                   "(object path: %s, uid: %d)",
                                   object_path, (int) act_user_get_uid (user));
                } else {
                        g_warning ("ActUserManager: user has no username (uid: %d)",
                                   (int) act_user_get_uid (user));
                }
                g_object_unref (user);
                goto out;
        }

        g_debug ("ActUserManager: user '%s' is now loaded", username);

        if (username_in_exclude_list (manager, username)) {
                g_debug ("ActUserManager: excluding user '%s'", username);
                g_object_unref (user);
                goto out;
        }

        old_user = g_hash_table_lookup (manager->priv->users_by_name, username);

        /* If username got added earlier by a different means, trump it now.
         */
        if (old_user != NULL) {
                g_debug ("ActUserManager: user '%s' was already known, "
                         "replacing with freshly loaded object", username);
                remove_user (manager, old_user);
        }

        add_user (manager, user);
        g_object_unref (user);

out:
        if (manager->priv->new_users_inhibiting_load == NULL) {
                g_debug ("ActUserManager: no pending users, trying to set loaded property");
                maybe_set_is_loaded (manager);
        } else {
                g_debug ("ActUserManager: not all users loaded yet");
        }
}

static ActUser *
add_new_user_for_object_path (const char     *object_path,
                              ActUserManager *manager)
{
        ActUser *user;

        user = g_hash_table_lookup (manager->priv->users_by_object_path, object_path); 

        if (user != NULL) {
                g_debug ("ActUserManager: tracking existing user %s with object path %s",
                         act_user_get_user_name (user), object_path);
                return user;
        }

        g_debug ("ActUserManager: tracking new user with object path %s", object_path);

        user = create_new_user (manager);
        _act_user_update_from_object_path (user, object_path);

        return user;
}

static void
on_new_user_in_accounts_service (GDBusProxy *proxy,
                                 const char *object_path,
                                 gpointer    user_data)
{
        ActUserManager *manager = ACT_USER_MANAGER (user_data);

        if (!manager->priv->is_loaded) {
                g_debug ("ActUserManager: ignoring new user in accounts service with object path %s since not loaded yet", object_path);
                return;
        }

        g_debug ("ActUserManager: new user in accounts service with object path %s", object_path);
        add_new_user_for_object_path (object_path, manager);
}

static void
on_user_removed_in_accounts_service (GDBusProxy *proxy,
                                     const char *object_path,
                                     gpointer    user_data)
{
        ActUserManager *manager = ACT_USER_MANAGER (user_data);
        ActUser        *user;

        user = g_hash_table_lookup (manager->priv->users_by_object_path, object_path);

        if (user == NULL) {
                g_debug ("ActUserManager: ignoring untracked user %s", object_path);
                return;
        } else {
                g_debug ("ActUserManager: tracked user %s removed from accounts service", object_path);
        }

        manager->priv->new_users = g_slist_remove (manager->priv->new_users, user);

        remove_user (manager, user);
}

static void
on_get_current_session_finished (GObject        *object,
                                 GAsyncResult   *result,
                                 gpointer        data)
{
        ConsoleKitManager *proxy = CONSOLE_KIT_MANAGER (object);
        ActUserManager    *manager = data;
        GError            *error = NULL;
        char              *session_id;

        g_assert (manager->priv->seat.state == ACT_USER_MANAGER_SEAT_STATE_GET_SESSION_ID);

        if (!console_kit_manager_call_get_current_session_finish (proxy, &session_id, result, &error)) {
                if (error != NULL) {
                        g_debug ("Failed to identify the current session: %s",
                                 error->message);
                        g_error_free (error);
                } else {
                        g_debug ("Failed to identify the current session");
                }
                unload_seat (manager);
                return;
        }

        manager->priv->seat.session_id = session_id;
        manager->priv->seat.state++;

        load_seat_incrementally (manager);
}

static void
get_current_session_id (ActUserManager *manager)
{
        console_kit_manager_call_get_current_session (manager->priv->ck_manager_proxy, NULL, on_get_current_session_finished, manager);
}

static void
unload_new_session (ActUserManagerNewSession *new_session)
{
        ActUserManager *manager;

        manager = new_session->manager;

        manager->priv->new_sessions = g_slist_remove (manager->priv->new_sessions,
                                                      new_session);

        if (new_session->proxy != NULL) {
                g_object_unref (new_session->proxy);
        }

        g_free (new_session->x11_display);
        g_free (new_session->id);

        g_slice_free (ActUserManagerNewSession, new_session);
}

static void
get_proxy_for_new_session (ActUserManagerNewSession *new_session)
{
        GError            *error = NULL;

        new_session->proxy = console_kit_session_proxy_new_sync (new_session->manager->priv->connection,
                                                                 G_DBUS_PROXY_FLAGS_NONE,
                                                                 CK_NAME,
                                                                 new_session->id,
                                                                 NULL,
                                                                 &error);
        if (new_session->proxy == NULL) {
                g_warning ("Failed to connect to the ConsoleKit '%s' object: %s",
                           new_session->id, error->message);
                g_error_free (error);
                unload_new_session (new_session);
                return;
        }

        new_session->state++;

        load_new_session_incrementally (new_session);
}

static void
on_get_unix_user_finished (GObject      *object,
                           GAsyncResult *result,
                           gpointer      data)
{
        ConsoleKitSession *proxy = CONSOLE_KIT_SESSION (object);
        ActUserManagerNewSession *new_session = data;
        GError            *error = NULL;
        guint              uid;

        if (!console_kit_session_call_get_unix_user_finish (proxy, &uid, result, &error)) {
                if (error != NULL) {
                        g_debug ("Failed to get uid of session '%s': %s",
                                 new_session->id, error->message);
                        g_error_free (error);
                } else {
                        g_debug ("Failed to get uid of session '%s'",
                                 new_session->id);
                }
                unload_new_session (new_session);
                return;
        }

        g_debug ("ActUserManager: Found uid of session '%s': %u",
                 new_session->id, uid);

        new_session->uid = (uid_t) uid;
        new_session->state++;

        load_new_session_incrementally (new_session);
}

static void
get_uid_for_new_session (ActUserManagerNewSession *new_session)
{
        g_assert (new_session->proxy != NULL);

        console_kit_session_call_get_unix_user (new_session->proxy,
                                                NULL,
                                                on_get_unix_user_finished,
                                                new_session);
}

static void
on_find_user_by_name_finished (GObject       *object,
                               GAsyncResult  *result,
                               gpointer       data)
{
        AccountsAccounts *proxy = ACCOUNTS_ACCOUNTS (object);
        ActUserManagerFetchUserRequest *request = data;
        GError          *error = NULL;
        char            *user;

        if (!accounts_accounts_call_find_user_by_name_finish (proxy, &user, result, &error)) {
                if (error != NULL) {
                        g_debug ("ActUserManager: Failed to find user %s: %s",
                                 request->username, error->message);
                        g_error_free (error);
                } else {
                        g_debug ("ActUserManager: Failed to find user %s",
                                 request->username);
                }
                give_up (request->manager, request);
                return;
        }

        g_debug ("ActUserManager: Found object path of user '%s': %s",
                 request->username, user);
        request->object_path = user;
        request->state++;

        fetch_user_incrementally (request);
}

static void
find_user_in_accounts_service (ActUserManager                 *manager,
                               ActUserManagerFetchUserRequest *request)
{
        g_debug ("ActUserManager: Looking for user %s in accounts service",
                 request->username);

        g_assert (manager->priv->accounts_proxy != NULL);

        accounts_accounts_call_find_user_by_name (manager->priv->accounts_proxy,
                                                  request->username,
                                                  NULL,
                                                  on_find_user_by_name_finished,
                                                  request);
}

static void
set_is_loaded (ActUserManager *manager,
               gboolean        is_loaded)
{
        if (manager->priv->is_loaded != is_loaded) {
                manager->priv->is_loaded = is_loaded;
                g_object_notify (G_OBJECT (manager), "is-loaded");
        }
}

static void
on_list_cached_users_finished (GObject      *object,
                               GAsyncResult *result,
                               gpointer      data)
{
        AccountsAccounts *proxy = ACCOUNTS_ACCOUNTS (object);
        ActUserManager   *manager = data;
        gchar           **user_paths;
        GError           *error = NULL;

        manager->priv->listing_cached_users = FALSE;
        if (!accounts_accounts_call_list_cached_users_finish (proxy, &user_paths, result, &error)) {
                g_debug ("ActUserManager: ListCachedUsers failed: %s", error->message);
                g_error_free (error);

                g_object_unref (manager->priv->accounts_proxy);
                manager->priv->accounts_proxy = NULL;

                return;
        }

        /* We now have a batch of unloaded users that we know about. Once that initial
         * batch is loaded up, we can mark the manager as loaded.
         *
         * (see on_new_user_loaded)
         */
        if (g_strv_length (user_paths) > 0) {
                int i;

                g_debug ("ActUserManager: ListCachedUsers finished, will set loaded property after list is fully loaded");
                for (i = 0; user_paths[i] != NULL; i++) {
                        ActUser *user;

                        user = add_new_user_for_object_path (user_paths[i], manager);
                        if (!manager->priv->is_loaded) {
                                manager->priv->new_users_inhibiting_load = g_slist_prepend (manager->priv->new_users_inhibiting_load, user);
                        }
                }
        } else {
                g_debug ("ActUserManager: ListCachedUsers finished with empty list, maybe setting loaded property now");
                maybe_set_is_loaded (manager);
        }

        g_strfreev (user_paths);

        /* Add users who are specifically included */
        if (manager->priv->include_usernames != NULL) {
                GSList *l;

                for (l = manager->priv->include_usernames; l != NULL; l = l->next) {
                        ActUser *user;

                        g_debug ("ActUserManager: Adding included user %s", (char *)l->data);
                        /*
                         * The call to act_user_manager_get_user will add the user if it is
                         * valid and not already in the hash.
                         */
                        user = act_user_manager_get_user (manager, l->data);
                        if (user == NULL) {
                                g_debug ("ActUserManager: unable to lookup user '%s'", (char *)l->data);
                        }
                }
        }
}

static void
on_get_x11_display_finished (GObject      *object,
                             GAsyncResult *result,
                             gpointer      data)
{
        ConsoleKitSession *proxy = CONSOLE_KIT_SESSION (object);
        ActUserManagerNewSession *new_session = data;
        GError            *error = NULL;
        char              *x11_display;

        if (!console_kit_session_call_get_x11_display_finish (proxy, &x11_display, result, &error)) {
                if (error != NULL) {
                        g_debug ("Failed to get the x11 display of session '%s': %s",
                                 new_session->id, error->message);
                        g_error_free (error);
                } else {
                        g_debug ("Failed to get the x11 display of session '%s'",
                                 new_session->id);
                }
                unload_new_session (new_session);
                return;
        }
  
        g_debug ("ActUserManager: Found x11 display of session '%s': %s",
                 new_session->id, x11_display);

        new_session->x11_display = x11_display;
        new_session->state++;

        load_new_session_incrementally (new_session);
}

static void
get_x11_display_for_new_session (ActUserManagerNewSession *new_session)
{
        g_assert (new_session->proxy != NULL);

        console_kit_session_call_get_x11_display (new_session->proxy,
                                                  NULL,
                                                  on_get_x11_display_finished,
                                                  new_session);
}

static gboolean
get_pwent_for_uid (uid_t           uid,
                   struct passwd **pwentp)
{
        struct passwd *pwent;

        do {
                errno = 0;
                pwent = getpwuid (uid);
        } while (pwent == NULL && errno == EINTR);

        if (pwentp != NULL) {
                *pwentp = pwent;
        }

        return (pwent != NULL);
}

static void
maybe_add_new_session (ActUserManagerNewSession *new_session)
{
        ActUserManager *manager;
        struct passwd  *pwent;
        ActUser        *user;

        manager = ACT_USER_MANAGER (new_session->manager);

        if (new_session->x11_display == NULL || new_session->x11_display[0] == '\0') {
                g_debug ("AcUserManager: ignoring session '%s' since it's not graphical",
                         new_session->id);
                goto done;
        }

        if (session_is_login_window (manager, new_session->id)) {
                goto done;
        }

        errno = 0;
        get_pwent_for_uid (new_session->uid, &pwent);
        if (pwent == NULL) {
                g_warning ("Unable to lookup user ID %d: %s",
                           (int) new_session->uid, g_strerror (errno));
                goto failed;
        }

        /* check exclusions up front */
        if (username_in_exclude_list (manager, pwent->pw_name)) {
                g_debug ("ActUserManager: excluding user '%s'", pwent->pw_name);
                goto failed;
        }

        user = act_user_manager_get_user (manager, pwent->pw_name);
        if (user == NULL) {
                return;
        }

        add_session_for_user (manager, user, new_session->id);

        /* if we haven't yet gotten the login frequency
           then at least add one because the session exists */
        if (act_user_get_login_frequency (user) == 0) {
                _act_user_update_login_frequency (user, 1);
        }

done:
        new_session->state = ACT_USER_MANAGER_NEW_SESSION_STATE_LOADED;
        unload_new_session (new_session);
        return;

failed:
        unload_new_session (new_session);
}

static void
load_new_session (ActUserManager *manager,
                  const char     *session_id)
{
        ActUserManagerNewSession *new_session;

        new_session = g_slice_new0 (ActUserManagerNewSession);

        new_session->manager = manager;
        new_session->id = g_strdup (session_id);
        new_session->state = ACT_USER_MANAGER_NEW_SESSION_STATE_UNLOADED + 1;

        manager->priv->new_sessions = g_slist_prepend (manager->priv->new_sessions,
                                                       new_session);
        load_new_session_incrementally (new_session);
}

static void
seat_session_added (GDBusProxy     *seat_proxy,
                    const char     *session_id,
                    ActUserManager *manager)
{
        g_debug ("ActUserManager: Session added: %s", session_id);

        load_new_session (manager, session_id);
}

static gint
match_new_session_cmpfunc (gconstpointer a,
                           gconstpointer b)
{
        ActUserManagerNewSession *new_session;
        const char               *session_id;

        new_session = (ActUserManagerNewSession *) a;
        session_id = (const char *) b;

        return strcmp (new_session->id, session_id);
}

static void
seat_session_removed (GDBusProxy     *seat_proxy,
                      const char     *session_id,
                      ActUserManager *manager)
{
        ActUser       *user;
        GSList        *found;
        char          *username;

        g_debug ("ActUserManager: Session removed: %s", session_id);

        found = g_slist_find_custom (manager->priv->new_sessions,
                                     session_id,
                                     match_new_session_cmpfunc);

        if (found != NULL) {
                ActUserManagerNewSession *new_session;

                new_session = (ActUserManagerNewSession *) found->data;

                if (new_session->state > ACT_USER_MANAGER_NEW_SESSION_STATE_GET_X11_DISPLAY) {
                        g_debug ("ActUserManager: New session for uid %d on "
                                 "x11 display %s removed before fully loading",
                                 (int) new_session->uid, new_session->x11_display);
                } else if (new_session->state > ACT_USER_MANAGER_NEW_SESSION_STATE_GET_UID) {
                        g_debug ("ActUserManager: New session for uid %d "
                                 "removed before fully loading",
                                 (int) new_session->uid);
                } else {
                        g_debug ("ActUserManager: New session removed "
                                 "before fully loading");
                }
                unload_new_session (new_session);
                return;
        }

        /* since the session object may already be gone
         * we can't query CK directly */

        username = g_hash_table_lookup (manager->priv->sessions, session_id);
        if (username == NULL) {
                return;
        }

        user = g_hash_table_lookup (manager->priv->users_by_name, username);
        if (user == NULL) {
                /* nothing to do */
                return;
        }

        g_debug ("ActUserManager: Session removed for %s", username);
        _act_user_remove_session (user, session_id);
}

static void
get_seat_proxy (ActUserManager *manager)
{
        GError *error = NULL;

        g_assert (manager->priv->seat.seat_proxy == NULL);

        manager->priv->seat.seat_proxy = console_kit_seat_proxy_new_sync (manager->priv->connection,
                                                                          G_DBUS_PROXY_FLAGS_NONE,
                                                                          CK_NAME,
                                                                          manager->priv->seat.id,
                                                                          NULL,
                                                                          &error);
        if (manager->priv->seat.seat_proxy == NULL) {
                if (error != NULL) {
                        g_warning ("Failed to connect to the ConsoleKit seat object: %s",
                                   error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Failed to connect to the ConsoleKit seat object");
                }
                unload_seat (manager);
                return;
        }

        g_signal_connect (manager->priv->seat.seat_proxy,
                          "session-added",
                          G_CALLBACK (seat_session_added),
                          manager);
        g_signal_connect (manager->priv->seat.seat_proxy,
                          "session-removed",
                          G_CALLBACK (seat_session_removed),
                          manager);
        manager->priv->seat.state++;
}

static void
get_session_proxy (ActUserManager *manager)
{
        GError *error = NULL;

        g_assert (manager->priv->seat.session_proxy == NULL);

        manager->priv->seat.session_proxy = console_kit_session_proxy_new_sync (manager->priv->connection,
                                                                                G_DBUS_PROXY_FLAGS_NONE,
                                                                                CK_NAME,
                                                                                manager->priv->seat.session_id,
                                                                                NULL,
                                                                                &error);
        if (manager->priv->seat.session_proxy == NULL) {
                if (error != NULL) {
                        g_warning ("Failed to connect to the ConsoleKit session object: %s",
                                   error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Failed to connect to the ConsoleKit session object");
                }
                unload_seat (manager);
                return;
        }

        manager->priv->seat.state++;
}

static void
unload_seat (ActUserManager *manager)
{
        manager->priv->seat.state = ACT_USER_MANAGER_SEAT_STATE_UNLOADED;

        if (manager->priv->seat.seat_proxy != NULL) {
                g_object_unref (manager->priv->seat.seat_proxy);
                manager->priv->seat.seat_proxy = NULL;
        }

        if (manager->priv->seat.session_proxy != NULL) {
                g_object_unref (manager->priv->seat.session_proxy);
                manager->priv->seat.session_proxy = NULL;
        }

        g_free (manager->priv->seat.id);
        manager->priv->seat.id = NULL;

        g_free (manager->priv->seat.session_id);
        manager->priv->seat.session_id = NULL;

        g_debug ("ActUserManager: seat unloaded, so trying to set loaded property");
        maybe_set_is_loaded (manager);
}

static void
load_new_session_incrementally (ActUserManagerNewSession *new_session)
{
        switch (new_session->state) {
        case ACT_USER_MANAGER_NEW_SESSION_STATE_GET_PROXY:
                get_proxy_for_new_session (new_session);
                break;
        case ACT_USER_MANAGER_NEW_SESSION_STATE_GET_UID:
                get_uid_for_new_session (new_session);
                break;
        case ACT_USER_MANAGER_NEW_SESSION_STATE_GET_X11_DISPLAY:
                get_x11_display_for_new_session (new_session);
                break;
        case ACT_USER_MANAGER_NEW_SESSION_STATE_MAYBE_ADD:
                maybe_add_new_session (new_session);
                break;
        case ACT_USER_MANAGER_NEW_SESSION_STATE_LOADED:
                break;
        default:
                g_assert_not_reached ();
        }
}

static void
free_fetch_user_request (ActUserManagerFetchUserRequest *request)
{
        ActUserManager *manager;

        manager = request->manager;

        manager->priv->fetch_user_requests = g_slist_remove (manager->priv->fetch_user_requests, request);
        g_free (request->username);
        g_free (request->object_path);
        g_slice_free (ActUserManagerFetchUserRequest, request);
}

static void
give_up (ActUserManager                 *manager,
         ActUserManagerFetchUserRequest *request)
{

        g_debug ("ActUserManager: account service unavailable, "
                 "giving up");
        request->state = ACT_USER_MANAGER_GET_USER_STATE_UNFETCHED;
}

static void
on_user_manager_maybe_ready_for_request (ActUserManager                 *manager,
                                         GParamSpec                     *pspec,
                                         ActUserManagerFetchUserRequest *request)
{
        if (!manager->priv->is_loaded) {
                return;
        }

        g_debug ("ActUserManager: user manager now loaded, proceeding with fetch user request for user '%s'",
                 request->username);

        g_signal_handlers_disconnect_by_func (manager, on_user_manager_maybe_ready_for_request, request);

        request->state++;
        fetch_user_incrementally (request);
}

static void
fetch_user_incrementally (ActUserManagerFetchUserRequest *request)
{
        ActUserManager *manager;

        g_debug ("ActUserManager: finding user %s state %d",
                 request->username, request->state);
        manager = request->manager;
        switch (request->state) {
        case ACT_USER_MANAGER_GET_USER_STATE_WAIT_FOR_LOADED:
                if (manager->priv->is_loaded) {
                        request->state++;
                        fetch_user_incrementally (request);
                } else {
                        g_debug ("ActUserManager: waiting for user manager to load before finding user %s",
                                 request->username);
                        g_signal_connect (manager, "notify::is-loaded",
                                          G_CALLBACK (on_user_manager_maybe_ready_for_request), request);

                }
                break;

        case ACT_USER_MANAGER_GET_USER_STATE_ASK_ACCOUNTS_SERVICE:
                if (manager->priv->accounts_proxy == NULL) {
                        give_up (manager, request);
                } else {
                        find_user_in_accounts_service (manager, request);
                }
                break;
        case ACT_USER_MANAGER_GET_USER_STATE_FETCHED:
                g_debug ("ActUserManager: user %s fetched", request->username);
                _act_user_update_from_object_path (request->user, request->object_path);
                break;
        case ACT_USER_MANAGER_GET_USER_STATE_UNFETCHED:
                g_debug ("ActUserManager: user %s was not fetched", request->username);
                break;
        default:
                g_assert_not_reached ();
        }

        if (request->state == ACT_USER_MANAGER_GET_USER_STATE_FETCHED  ||
            request->state == ACT_USER_MANAGER_GET_USER_STATE_UNFETCHED) {
                g_debug ("ActUserManager: finished handling request for user %s",
                         request->username);
                free_fetch_user_request (request);
        }
}

static void
fetch_user_from_accounts_service (ActUserManager *manager,
                                  ActUser        *user,
                                  const char     *username)
{
        ActUserManagerFetchUserRequest *request;

        request = g_slice_new0 (ActUserManagerFetchUserRequest);

        request->manager = manager;
        request->username = g_strdup (username);
        request->user = user;
        request->state = ACT_USER_MANAGER_GET_USER_STATE_UNFETCHED + 1;

        manager->priv->fetch_user_requests = g_slist_prepend (manager->priv->fetch_user_requests,
                                                              request);
        fetch_user_incrementally (request);
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

        user = g_hash_table_lookup (manager->priv->users_by_name, username);

        /* if we don't have it loaded try to load it now */
        if (user == NULL) {
                g_debug ("ActUserManager: trying to track new user with username %s", username);
                user = create_new_user (manager);

                if (manager->priv->accounts_proxy != NULL) {
                        fetch_user_from_accounts_service (manager, user, username);
                }
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
        g_hash_table_foreach (manager->priv->users_by_name, listify_hash_values_hfunc, &retval);

        return g_slist_sort (retval, (GCompareFunc) act_user_collate);
}

static void
maybe_set_is_loaded (ActUserManager *manager)
{
        if (manager->priv->is_loaded) {
                g_debug ("ActUserManager: already loaded, so not setting loaded property");
                return;
        }

        if (manager->priv->getting_sessions) {
                g_debug ("ActUserManager: GetSessions call pending, so not setting loaded property");
                return;
        }

        if (manager->priv->listing_cached_users) {
                g_debug ("ActUserManager: Listing cached users, so not setting loaded property");
                return;
        }

        if (manager->priv->new_users_inhibiting_load != NULL) {
                g_debug ("ActUserManager: Loading new users, so not setting loaded property");
                return;
        }

        /* Don't set is_loaded yet unless the seat is already loaded
         * or failed to load.
         */
        if (manager->priv->seat.state == ACT_USER_MANAGER_SEAT_STATE_LOADED) {
                g_debug ("ActUserManager: Seat loaded, so now setting loaded property");
        } else if (manager->priv->seat.state == ACT_USER_MANAGER_SEAT_STATE_UNLOADED) {
                g_debug ("ActUserManager: Seat wouldn't load, so giving up on it and setting loaded property");
        } else {
                g_debug ("ActUserManager: Seat still actively loading, so not setting loaded property");
                return;
        }

        set_is_loaded (manager, TRUE);
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
on_get_sessions_finished (GObject      *object,
                          GAsyncResult *result,
                          gpointer      data)
{
        ConsoleKitSeat *proxy = CONSOLE_KIT_SEAT (object);
        ActUserManager *manager = data;
        GError         *error = NULL;
        gchar         **session_ids;
        int             i;

        if (!console_kit_seat_call_get_sessions_finish (proxy, &session_ids, result, &error)) {
                if (error != NULL) {
                        g_warning ("unable to determine sessions for seat: %s",
                                   error->message);
                        g_error_free (error);
                } else {
                        g_warning ("unable to determine sessions for seat");
                }
                return;
        }

        manager->priv->getting_sessions = FALSE;
        for (i = 0; session_ids[i] != NULL; i++) {
                load_new_session (manager, session_ids[i]);
        }
        g_strfreev (session_ids);

        g_debug ("ActUserManager: GetSessions call finished, so trying to set loaded property");
        maybe_set_is_loaded (manager);
}

static void
load_sessions (ActUserManager *manager)
{
        if (manager->priv->seat.seat_proxy == NULL) {
                g_debug ("ActUserManager: no seat proxy; can't load sessions");
                return;
        }

        console_kit_seat_call_get_sessions (manager->priv->seat.seat_proxy,
                                            NULL,
                                            on_get_sessions_finished,
                                            manager);
        manager->priv->getting_sessions = TRUE;
}

static void
load_users (ActUserManager *manager)
{
        g_assert (manager->priv->accounts_proxy != NULL);
        g_debug ("ActUserManager: calling 'ListCachedUsers'");

        accounts_accounts_call_list_cached_users (manager->priv->accounts_proxy,
                                                  NULL, 
                                                  on_list_cached_users_finished,
                                                  manager);
        manager->priv->listing_cached_users = TRUE;
}

static void
load_seat_incrementally (ActUserManager *manager)
{
        switch (manager->priv->seat.state) {
        case ACT_USER_MANAGER_SEAT_STATE_GET_SESSION_ID:
                get_current_session_id (manager);
                break;
        case ACT_USER_MANAGER_SEAT_STATE_GET_SESSION_PROXY:
                get_session_proxy (manager);
                break;
        case ACT_USER_MANAGER_SEAT_STATE_GET_ID:
                get_seat_id_for_current_session (manager);
                break;
        case ACT_USER_MANAGER_SEAT_STATE_GET_SEAT_PROXY:
                get_seat_proxy (manager);
                break;
        case ACT_USER_MANAGER_SEAT_STATE_LOADED:
                break;
        default:
                g_assert_not_reached ();
        }

        if (manager->priv->seat.state == ACT_USER_MANAGER_SEAT_STATE_LOADED) {
                load_sessions (manager);
        }

        g_debug ("ActUserManager: Seat loading sequence complete, so trying to set loaded property");
        maybe_set_is_loaded (manager);
}

static gboolean
load_idle (ActUserManager *manager)
{
        manager->priv->seat.state = ACT_USER_MANAGER_SEAT_STATE_UNLOADED + 1;
        load_seat_incrementally (manager);
        load_users (manager);
        manager->priv->load_id = 0;

        return FALSE;
}

static void
queue_load_seat_and_users (ActUserManager *manager)
{
        if (manager->priv->load_id > 0) {
                return;
        }

        manager->priv->load_id = g_idle_add ((GSourceFunc)load_idle, manager);
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
        case PROP_IS_LOADED:
                g_value_set_boolean (value, manager->priv->is_loaded);
                break;
        case PROP_HAS_MULTIPLE_USERS:
                g_value_set_boolean (value, manager->priv->has_multiple_users);
                break;
        case PROP_INCLUDE_USERNAMES_LIST:
                g_value_set_pointer (value, manager->priv->include_usernames);
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
set_include_usernames (ActUserManager *manager,
                       GSList         *list)
{
        if (manager->priv->include_usernames != NULL) {
                g_slist_foreach (manager->priv->include_usernames, (GFunc) g_free, NULL);
                g_slist_free (manager->priv->include_usernames);
        }
        manager->priv->include_usernames = slist_deep_copy (list);
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
        case PROP_INCLUDE_USERNAMES_LIST:
                set_include_usernames (self, g_value_get_pointer (value));
                break;
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
                                         PROP_INCLUDE_USERNAMES_LIST,
                                         g_param_spec_pointer ("include-usernames-list",
                                                               NULL,
                                                               NULL,
                                                               G_PARAM_READWRITE));

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

/**
 * act_user_manager_queue_load:
 * @manager: a #ActUserManager
 *
 * Queue loading users into user manager. This must be called, and the
 * #ActUserManager:is-loaded property must be %TRUE before calling
 * act_user_manager_list_users()
 */
static void
act_user_manager_queue_load (ActUserManager *manager)
{
        g_return_if_fail (ACT_IS_USER_MANAGER (manager));

        if (! manager->priv->is_loaded) {
                queue_load_seat_and_users (manager);
        }
}

static void
act_user_manager_init (ActUserManager *manager)
{
        GError        *error;

        manager->priv = ACT_USER_MANAGER_GET_PRIVATE (manager);

        /* sessions */
        manager->priv->sessions = g_hash_table_new_full (g_str_hash,
                                                         g_str_equal,
                                                         g_free,
                                                         g_free);

        /* users */
        manager->priv->users_by_name = g_hash_table_new_full (g_str_hash,
                                                              g_str_equal,
                                                              g_free,
                                                              g_object_unref);

        manager->priv->users_by_object_path = g_hash_table_new_full (g_str_hash,
                                                                     g_str_equal,
                                                                     NULL,
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

        manager->priv->accounts_proxy = accounts_accounts_proxy_new_sync (manager->priv->connection,
                                                                          G_DBUS_PROXY_FLAGS_NONE,
                                                                          ACCOUNTS_NAME,
                                                                          ACCOUNTS_PATH,
                                                                          NULL,
                                                                          &error);
        if (manager->priv->accounts_proxy == NULL) {
                if (error != NULL) {
                        g_warning ("Failed to create accounts proxy: %s", error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Failed to create_accounts_proxy");
                }
                return;
        }

        g_signal_connect (manager->priv->accounts_proxy,
                          "user-added",
                          G_CALLBACK (on_new_user_in_accounts_service),
                          manager);
        g_signal_connect (manager->priv->accounts_proxy,
                          "user-deleted",
                          G_CALLBACK (on_user_removed_in_accounts_service),
                          manager);

        manager->priv->ck_manager_proxy = console_kit_manager_proxy_new_sync (manager->priv->connection,
                                                                              G_DBUS_PROXY_FLAGS_NONE,
                                                                              CK_NAME,
                                                                              CK_MANAGER_PATH,
                                                                              NULL,
                                                                              &error);
        if (manager->priv->ck_manager_proxy == NULL) {
                if (error != NULL) {
                        g_warning ("Failed to create ConsoleKit proxy: %s", error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Failed to create_ConsoleKit_proxy");
                }
                return;
        }

        manager->priv->seat.state = ACT_USER_MANAGER_SEAT_STATE_UNLOADED;
}

static void
act_user_manager_finalize (GObject *object)
{
        ActUserManager *manager;
        GSList         *node;

        g_return_if_fail (object != NULL);
        g_return_if_fail (ACT_IS_USER_MANAGER (object));

        manager = ACT_USER_MANAGER (object);

        g_return_if_fail (manager->priv != NULL);

        g_slist_foreach (manager->priv->new_sessions,
                         (GFunc) unload_new_session, NULL);
        g_slist_free (manager->priv->new_sessions);

        g_slist_foreach (manager->priv->fetch_user_requests,
                         (GFunc) free_fetch_user_request, NULL);
        g_slist_free (manager->priv->fetch_user_requests);

        g_slist_free (manager->priv->new_users_inhibiting_load);

        node = manager->priv->new_users;
        while (node != NULL) {
                ActUser *user;
                GSList  *next_node;

                user = ACT_USER (node->data);
                next_node = node->next;

                g_signal_handlers_disconnect_by_func (user, on_new_user_loaded, manager);
                g_object_unref (user);
                manager->priv->new_users = g_slist_delete_link (manager->priv->new_users, node);
                node = next_node;
        }

        unload_seat (manager);

        if (manager->priv->exclude_usernames != NULL) {
                g_slist_foreach (manager->priv->exclude_usernames, (GFunc) g_free, NULL);
                g_slist_free (manager->priv->exclude_usernames);
        }

        if (manager->priv->include_usernames != NULL) {
                g_slist_foreach (manager->priv->include_usernames, (GFunc) g_free, NULL);
                g_slist_free (manager->priv->include_usernames);
        }

        if (manager->priv->seat.seat_proxy != NULL) {
                g_object_unref (manager->priv->seat.seat_proxy);
        }

        if (manager->priv->seat.session_proxy != NULL) {
                g_object_unref (manager->priv->seat.session_proxy);
        }

        if (manager->priv->accounts_proxy != NULL) {
                g_object_unref (manager->priv->accounts_proxy);
        }

        if (manager->priv->load_id > 0) {
                g_source_remove (manager->priv->load_id);
                manager->priv->load_id = 0;
        }

        g_hash_table_destroy (manager->priv->sessions);

        g_hash_table_destroy (manager->priv->users_by_name);
        g_hash_table_destroy (manager->priv->users_by_object_path);

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
                act_user_manager_queue_load (user_manager_object);
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
        res = accounts_accounts_call_create_user_sync (manager->priv->accounts_proxy,
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

        user = add_new_user_for_object_path (path, manager);

        g_free (path);

        return user;
}

gboolean
act_user_manager_delete_user (ActUserManager  *manager,
                              ActUser         *user,
                              gboolean         remove_files,
                              GError         **error)
{
        GError *local_error;
        gboolean res;

        g_debug ("ActUserManager: Deleting user '%s' (uid %ld)", act_user_get_user_name (user), (long) act_user_get_uid (user));

        g_assert (manager->priv->accounts_proxy != NULL);

        local_error = NULL;
        if (!accounts_accounts_call_delete_user_sync (manager->priv->accounts_proxy,
                                                      act_user_get_uid (user),
                                                      remove_files,
                                                      NULL,
                                                      &local_error)) {
                g_propagate_error (error, local_error);
        }

        return res;
}

