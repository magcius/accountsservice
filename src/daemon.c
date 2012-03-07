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

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef HAVE_UTMPX_H
#include <utmpx.h>
#endif

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <polkit/polkit.h>

#include "daemon.h"
#include "util.h"

#define PATH_PASSWD "/etc/passwd"
#define PATH_SHADOW "/etc/shadow"
#define PATH_GDM_CUSTOM "/etc/gdm/custom.conf"

#define USERDIR LOCALSTATEDIR "/lib/AccountsService/users"

static const char *default_excludes[] = {
        "bin",
        "root",
        "daemon",
        "adm",
        "lp",
        "sync",
        "shutdown",
        "halt",
        "mail",
        "news",
        "uucp",
        "operator",
        "nobody",
        "nobody4",
        "noaccess",
        "postgres",
        "pvm",
        "rpm",
        "nfsnobody",
        "pcap",
        NULL
};

enum {
        PROP_0,
        PROP_DAEMON_VERSION
};

struct DaemonPrivate {
        GDBusConnection *bus_connection;
        GDBusProxy *bus_proxy;

        GHashTable *users;
        GHashTable *exclusions;

        User *autologin;

        GFileMonitor *passwd_monitor;
        GFileMonitor *shadow_monitor;
        GFileMonitor *gdm_monitor;

        guint reload_id;
        guint autologin_id;

        PolkitAuthority *authority;
};

static void daemon_accounts_accounts_iface_init (AccountsAccountsIface *iface);

G_DEFINE_TYPE_WITH_CODE (Daemon, daemon, ACCOUNTS_TYPE_ACCOUNTS_SKELETON, G_IMPLEMENT_INTERFACE (ACCOUNTS_TYPE_ACCOUNTS, daemon_accounts_accounts_iface_init));

#define DAEMON_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), TYPE_DAEMON, DaemonPrivate))

static const GDBusErrorEntry accounts_error_entries[] =
{ 
        { ERROR_FAILED, "org.freedesktop.Accounts.Error.Failed" },
        { ERROR_USER_EXISTS, "org.freedesktop.Accounts.Error.UserExists" },
        { ERROR_USER_DOES_NOT_EXIST, "org.freedesktop.Accounts.Error.UserDoesNotExist" },
        { ERROR_PERMISSION_DENIED, "org.freedesktop.Accounts.Error.PermissionDenied" },
        { ERROR_NOT_SUPPORTED, "org.freedesktop.Accounts.Error.NotSupported" }
};

GQuark
error_quark (void)
{
        static volatile gsize quark_volatile = 0;

        g_dbus_error_register_error_domain ("accounts_error",
                                            &quark_volatile,
                                            accounts_error_entries,
                                            G_N_ELEMENTS (accounts_error_entries));

        return (GQuark) quark_volatile;
}
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
error_get_type (void)
{
  static GType etype = 0;

  if (etype == 0)
    {
      static const GEnumValue values[] =
        {
          ENUM_ENTRY (ERROR_FAILED, "Failed"),
          ENUM_ENTRY (ERROR_USER_EXISTS, "UserExists"),
          ENUM_ENTRY (ERROR_USER_DOES_NOT_EXIST, "UserDoesntExist"),
          ENUM_ENTRY (ERROR_PERMISSION_DENIED, "PermissionDenied"),
          ENUM_ENTRY (ERROR_NOT_SUPPORTED, "NotSupported"),
          { 0, 0, 0 }
        };
      g_assert (NUM_ERRORS == G_N_ELEMENTS (values) - 1);
      etype = g_enum_register_static ("Error", values);
    }
  return etype;
}

gboolean
daemon_local_user_is_excluded (Daemon *daemon, const gchar *username, uid_t uid)
{
        if (g_hash_table_lookup (daemon->priv->exclusions, username)) {
                return TRUE;
        }

        return FALSE;
}

static void
reload_wtmp_history (Daemon *daemon)
{
#ifdef HAVE_UTMPX_H
        struct utmpx *wtmp_entry;
        GHashTable *login_frequency_hash;
        GHashTableIter iter;
        gpointer key, value;

#ifdef UTXDB_LOG
        if (setutxdb (UTXDB_LOG, NULL) != 0)
                return;
#else
        utmpxname (_PATH_WTMPX);
        setutxent ();
#endif

        login_frequency_hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

        while ((wtmp_entry = getutxent ())) {
                if (wtmp_entry->ut_type != USER_PROCESS)
                        continue;

                if (wtmp_entry->ut_user[0] == 0)
                        continue;

                if (daemon_local_user_is_excluded (daemon,
                                                   wtmp_entry->ut_user,
                                                   daemon->priv->minimal_uid)) {
                        g_debug ("excluding user '%s'", wtmp_entry->ut_user);
                        continue;
                }

                if (!g_hash_table_lookup_extended (login_frequency_hash,
                                                   wtmp_entry->ut_user,
                                                   &key, &value)) {
                        g_hash_table_insert (login_frequency_hash,
                                             g_strdup (wtmp_entry->ut_user),
                                             GUINT_TO_POINTER (1));
                } else {
                        guint frequency;

                        frequency = GPOINTER_TO_UINT (value) + 1;

                        g_hash_table_insert (login_frequency_hash,
                                             key,
                                             GUINT_TO_POINTER (frequency));
                }

        }
        endutxent ();

        g_hash_table_iter_init (&iter, login_frequency_hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                User *user;
                char *username = (char *) key;
                guint64 frequency = (guint64) GPOINTER_TO_UINT (value);

                user = daemon_local_find_user_by_name (daemon, username);
                if (user == NULL) {
                        g_debug ("unable to lookup user '%s'", username);
                        continue;
                }

                g_object_set (user, "login-frequency", frequency, NULL);
        }

        g_hash_table_foreach (login_frequency_hash, (GHFunc) g_free, NULL);
        g_hash_table_unref (login_frequency_hash);
#endif /* HAVE_UTMPX_H */
}

static void
listify_hash_values_hfunc (gpointer key,
                           gpointer value,
                           gpointer user_data)
{
        GSList **list = user_data;

        *list = g_slist_prepend (*list, value);
}

static gint
compare_user_name (gconstpointer a, gconstpointer b)
{
        User *user = (User *)a;
        const gchar *name = b;

        return g_strcmp0 (user_local_get_user_name (user), name);
}

static void
reload_passwd (Daemon *daemon)
{
        struct passwd *pwent;
        GSList *old_users;
        GSList *new_users;
        GSList *list;
#ifdef HAVE_FGETPWENT
        FILE *fp;
#endif
        User *user = NULL;

        old_users = NULL;
        new_users = NULL;

#ifdef HAVE_FGETPWENT
        errno = 0;
        fp = fopen (PATH_PASSWD, "r");
        if (fp == NULL) {
                g_warning ("Unable to open %s: %s", PATH_PASSWD, g_strerror (errno));
                goto out;
        }
#else
        setpwent();
#endif
        g_hash_table_foreach (daemon->priv->users, listify_hash_values_hfunc, &old_users);
        g_slist_foreach (old_users, (GFunc) g_object_ref, NULL);

#ifdef HAVE_FGETPWENT
        while ((pwent = fgetpwent (fp)) != NULL) {
#else
        while ((pwent = getpwent ()) != NULL) {
#endif
                /* Skip users below MINIMAL_UID... */
                if (daemon_local_user_is_excluded (daemon, pwent->pw_name, pwent->pw_uid)) {
                        g_debug ("skipping user: %s", pwent->pw_name);
                        continue;
                }

                /* ignore duplicate entries */
                if (g_slist_find_custom (new_users, pwent->pw_name, compare_user_name)) {
                        continue;
                }

                user = g_hash_table_lookup (daemon->priv->users, pwent->pw_name);
                if (user == NULL) {
                        user = user_local_new (daemon, pwent->pw_uid);
                } else {
                        g_object_ref (user);
                }

                /* freeze & update users not already in the new list */
                g_object_freeze_notify (G_OBJECT (user));
                user_local_update_from_pwent (user, pwent);

                new_users = g_slist_prepend (new_users, user);
        }

        /* Go through and handle removed users */
        for (list = old_users; list; list = list->next) {
                user = list->data;
                if (! g_slist_find (new_users, user)) {
                        accounts_accounts_emit_user_deleted (ACCOUNTS_ACCOUNTS (daemon), user_local_get_object_path (user));
                        user_local_unregister (user);
                        g_hash_table_remove (daemon->priv->users,
                                             user_local_get_user_name (user));
                }
        }

        /* Go through and handle added users or update display names */
        for (list = new_users; list; list = list->next) {
                user = list->data;
                if (!g_slist_find (old_users, user)) {
                       user_local_register (user);
                       g_hash_table_insert (daemon->priv->users,
                                            g_strdup (user_local_get_user_name (user)),
                                            g_object_ref (user));

                        accounts_accounts_emit_user_added (ACCOUNTS_ACCOUNTS (daemon), user_local_get_object_path (user));
                }
        }

#ifdef HAVE_FGETPWENT
 out:
        /* Cleanup */

        fclose (fp);
#endif

        g_slist_foreach (new_users, (GFunc) g_object_thaw_notify, NULL);
        g_slist_foreach (new_users, (GFunc) g_object_unref, NULL);
        g_slist_free (new_users);

        g_slist_foreach (old_users, (GFunc) g_object_unref, NULL);
        g_slist_free (old_users);
}

static void
reload_data (Daemon *daemon)
{
        GHashTableIter iter;
        const gchar *name;
        User *user;
        GKeyFile *key_file;
        gchar *filename;

        g_hash_table_iter_init (&iter, daemon->priv->users);
        while (g_hash_table_iter_next (&iter, (gpointer *)&name, (gpointer *)&user)) {
                filename = g_build_filename (USERDIR, name, NULL);
                key_file = g_key_file_new ();
                if (g_key_file_load_from_file (key_file, filename, 0, NULL))
                        user_local_update_from_keyfile (user, key_file);
                g_key_file_free (key_file);
                g_free (filename);
        }
}

static void
reload_users (Daemon *daemon)
{
        reload_passwd (daemon);
        reload_wtmp_history (daemon);
        reload_data (daemon);
}

static gboolean
reload_users_timeout (Daemon *daemon)
{
        reload_users (daemon);
        daemon->priv->reload_id = 0;

        return FALSE;
}

static gboolean load_autologin (Daemon    *daemon,
                                gchar    **name,
                                gboolean  *enabled,
                                GError   **error);

static gboolean
reload_autologin_timeout (Daemon *daemon)
{
        gboolean enabled;
        gchar *name = NULL;
        GError *error = NULL;
        User *user = NULL;

        daemon->priv->autologin_id = 0;

        if (!load_autologin (daemon, &name, &enabled, &error)) {
                g_debug ("failed to load gdms custom.conf: %s", error->message);
                g_error_free (error);
                g_free (name);

                return FALSE;
        }

        if (enabled && name)
                user = daemon_local_find_user_by_name (daemon, name);

        if (daemon->priv->autologin != NULL && daemon->priv->autologin != user) {
                g_object_set (daemon->priv->autologin, "automatic-login", FALSE, NULL);
                g_signal_emit_by_name (daemon->priv->autologin, "changed", 0);
                g_object_unref (daemon->priv->autologin);
                daemon->priv->autologin = NULL;
        }

        if (enabled) {
                g_debug ("automatic login is enabled for '%s'\n", name);
                if (daemon->priv->autologin != user) {
                        g_object_set (user, "automatic-login", TRUE, NULL);
                        daemon->priv->autologin = g_object_ref (user);
                        g_signal_emit_by_name (daemon->priv->autologin, "changed", 0);
                }
        }
        else {
                g_debug ("automatic login is disabled\n");
        }

        g_free (name);

        return FALSE;
}

static void
queue_reload_users_soon (Daemon *daemon)
{
        if (daemon->priv->reload_id > 0) {
                return;
        }

        /* we wait half a second or so in case /etc/passwd and
         * /etc/shadow are changed at the same time, or repeatedly.
         */
        daemon->priv->reload_id = g_timeout_add (500, (GSourceFunc)reload_users_timeout, daemon);
}

static void
queue_reload_users (Daemon *daemon)
{
        if (daemon->priv->reload_id > 0) {
                return;
        }

        daemon->priv->reload_id = g_idle_add ((GSourceFunc)reload_users_timeout, daemon);
}

static void
queue_reload_autologin (Daemon *daemon)
{
        if (daemon->priv->autologin_id > 0) {
                return;
        }

        daemon->priv->autologin_id = g_idle_add ((GSourceFunc)reload_autologin_timeout, daemon);
}

static void
on_passwd_monitor_changed (GFileMonitor      *monitor,
                           GFile             *file,
                           GFile             *other_file,
                           GFileMonitorEvent  event_type,
                           Daemon            *daemon)
{
        if (event_type != G_FILE_MONITOR_EVENT_CHANGED &&
            event_type != G_FILE_MONITOR_EVENT_CREATED) {
                return;
        }

        queue_reload_users_soon (daemon);
}

static void
on_gdm_monitor_changed (GFileMonitor      *monitor,
                        GFile             *file,
                        GFile             *other_file,
                        GFileMonitorEvent  event_type,
                        Daemon            *daemon)
{
        if (event_type != G_FILE_MONITOR_EVENT_CHANGED &&
            event_type != G_FILE_MONITOR_EVENT_CREATED) {
                return;
        }

        queue_reload_autologin (daemon);
}

static void
daemon_init (Daemon *daemon)
{
        gint i;
        GFile *file;
        GError *error;

        daemon->priv = DAEMON_GET_PRIVATE (daemon);

        daemon->priv->exclusions = g_hash_table_new_full (g_str_hash,
                                                          g_str_equal,
                                                          g_free,
                                                          NULL);

        for (i = 0; default_excludes[i] != NULL; i++) {
                g_hash_table_insert (daemon->priv->exclusions,
                                     g_strdup (default_excludes[i]),
                                     GUINT_TO_POINTER (TRUE));
        }

        daemon->priv->users = g_hash_table_new_full (g_str_hash,
                                                     g_str_equal,
                                                     g_free,
                                                     (GDestroyNotify) g_object_unref);
        file = g_file_new_for_path (PATH_PASSWD);
        daemon->priv->passwd_monitor = g_file_monitor_file (file,
                                                            G_FILE_MONITOR_NONE,
                                                            NULL,
                                                            &error);
        g_object_unref (file);
        file = g_file_new_for_path (PATH_SHADOW);
        daemon->priv->shadow_monitor = g_file_monitor_file (file,
                                                            G_FILE_MONITOR_NONE,
                                                            NULL,
                                                            &error);
        g_object_unref (file);
        file = g_file_new_for_path (PATH_GDM_CUSTOM);
        daemon->priv->gdm_monitor = g_file_monitor_file (file,
                                                         G_FILE_MONITOR_NONE,
                                                         NULL,
                                                         &error);
        g_object_unref (file);

        if (daemon->priv->passwd_monitor != NULL) {
                g_signal_connect (daemon->priv->passwd_monitor,
                                  "changed",
                                  G_CALLBACK (on_passwd_monitor_changed),
                                  daemon);
        } else {
                g_warning ("Unable to monitor %s: %s", PATH_PASSWD, error->message);
                g_error_free (error);
        }
        if (daemon->priv->shadow_monitor != NULL) {
                g_signal_connect (daemon->priv->shadow_monitor,
                                  "changed",
                                  G_CALLBACK (on_passwd_monitor_changed),
                                  daemon);
        } else {
                g_warning ("Unable to monitor %s: %s", PATH_SHADOW, error->message);
                g_error_free (error);
       }
        if (daemon->priv->gdm_monitor != NULL) {
                g_signal_connect (daemon->priv->gdm_monitor,
                                  "changed",
                                  G_CALLBACK (on_gdm_monitor_changed),
                                  daemon);
        } else {
                g_warning ("Unable to monitor %s: %s", PATH_GDM_CUSTOM, error->message);
                g_error_free (error);
        }

        queue_reload_users (daemon);
        queue_reload_autologin (daemon);
}

static void
daemon_finalize (GObject *object)
{
        Daemon *daemon;

        g_return_if_fail (IS_DAEMON (object));

        daemon = DAEMON (object);

        if (daemon->priv->bus_proxy != NULL)
                g_object_unref (daemon->priv->bus_proxy);

        if (daemon->priv->bus_connection != NULL)
                g_object_unref (daemon->priv->bus_connection);

        g_hash_table_destroy (daemon->priv->users);

        G_OBJECT_CLASS (daemon_parent_class)->finalize (object);
}

static gboolean
register_accounts_daemon (Daemon *daemon)
{
        GError *error = NULL;

        daemon->priv->authority = polkit_authority_get_sync (NULL, &error);

        if (daemon->priv->authority == NULL) {
                if (error != NULL) {
                        g_critical ("error getting polkit authority: %s", error->message);
                        g_error_free (error);
                }
                goto error;
        }

        daemon->priv->bus_connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
        if (daemon->priv->bus_connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                goto error;
        }

        if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (daemon),
                                               daemon->priv->bus_connection,
                                               "/org/freedesktop/Accounts",
                                               &error)) {
                if (error != NULL) {
                        g_critical ("error exporting interface: %s", error->message);
                        g_error_free (error);
                }
                goto error;     
        }

        return TRUE;

 error:
        return FALSE;
}

Daemon *
daemon_new (void)
{
        Daemon *daemon;

        daemon = DAEMON (g_object_new (TYPE_DAEMON, NULL));

        if (!register_accounts_daemon (DAEMON (daemon))) {
                g_object_unref (daemon);
                goto error;
        }

        return daemon;

 error:
        return NULL;
}

static void
throw_error (GDBusMethodInvocation *context,
             gint                   error_code,
             const gchar           *format,
             ...)
{
        va_list args;
        gchar *message;

        va_start (args, format);
        message = g_strdup_vprintf (format, args);
        va_end (args);

        g_dbus_method_invocation_return_error (context, ERROR, error_code, "%s", message);

        g_free (message);
}

static User *
add_new_user_for_pwent (Daemon        *daemon,
                        struct passwd *pwent)
{
        User *user;

        user = user_local_new (daemon, pwent->pw_uid);
        user_local_update_from_pwent (user, pwent);
        user_local_register (user);

        g_hash_table_insert (daemon->priv->users,
                             g_strdup (user_local_get_user_name (user)),
                             user);

        accounts_accounts_emit_user_added (ACCOUNTS_ACCOUNTS (daemon), user_local_get_object_path (user));

        return user;
}

User *
daemon_local_find_user_by_id (Daemon *daemon,
                              uid_t   uid)
{
        User *user;
        struct passwd *pwent;

        pwent = getpwuid (uid);
        if (pwent == NULL) {
                g_debug ("unable to lookup uid %d", (int)uid);
                return NULL;
        }

        user = g_hash_table_lookup (daemon->priv->users, pwent->pw_name);

        if (user == NULL)
                user = add_new_user_for_pwent (daemon, pwent);

        return user;
}

User *
daemon_local_find_user_by_name (Daemon      *daemon,
                                const gchar *name)
{
        User *user;
        struct passwd *pwent;

        pwent = getpwnam (name);
        if (pwent == NULL) {
                g_debug ("unable to lookup name %s", name);
                return NULL;
        }

        user = g_hash_table_lookup (daemon->priv->users, pwent->pw_name);

        if (user == NULL)
                user = add_new_user_for_pwent (daemon, pwent);

        return user;
}

static gboolean
daemon_find_user_by_id (AccountsAccounts      *accounts,
                        GDBusMethodInvocation *context,
                        gint64                 uid)
{
        Daemon *daemon = (Daemon*)accounts;
        User *user;

        user = daemon_local_find_user_by_id (daemon, uid);

        if (user) {
                accounts_accounts_complete_find_user_by_id (NULL, context, user_local_get_object_path (user));
        }
        else {
                throw_error (context, ERROR_FAILED, "Failed to look up user with uid %d.", (int)uid);
        }

        return TRUE;
}

static gboolean
daemon_find_user_by_name (AccountsAccounts      *accounts,
                          GDBusMethodInvocation *context,
                          const gchar           *name)
{
        Daemon *daemon = (Daemon*)accounts;
        User *user;

        user = daemon_local_find_user_by_name (daemon, name);

        if (user) {
                accounts_accounts_complete_find_user_by_name (NULL, context, user_local_get_object_path (user));
        }
        else {
                throw_error (context, ERROR_FAILED, "Failed to look up user with name %s.", name);
        }

        return TRUE;
}

typedef struct {
        Daemon *daemon;
        GDBusMethodInvocation *context;
} ListUserData;


static ListUserData *
list_user_data_new (Daemon                *daemon,
                    GDBusMethodInvocation *context)
{
        ListUserData *data;

        data = g_new0 (ListUserData, 1);

        data->daemon = g_object_ref (daemon);
        data->context = context;

        return data;
}

static void
list_user_data_free (ListUserData *data)
{
        g_object_unref (data->daemon);
        g_free (data);
}

static gboolean
finish_list_cached_users (gpointer user_data)
{
        ListUserData *data = user_data;
        GPtrArray *object_paths;
        GHashTableIter iter;
        const gchar *name;
        User *user;
        uid_t uid;

        object_paths = g_ptr_array_new ();

        g_hash_table_iter_init (&iter, data->daemon->priv->users);
        while (g_hash_table_iter_next (&iter, (gpointer *)&name, (gpointer *)&user)) {
                uid = user_local_get_uid (user);
                if (!daemon_local_user_is_excluded (data->daemon, name, uid)) {
                        g_debug ("user %s %ld not excluded\n", name, (long) uid);
                        g_ptr_array_add (object_paths, (gpointer) user_local_get_object_path (user));
                }
        }
        g_ptr_array_add (object_paths, NULL);

        accounts_accounts_complete_list_cached_users (NULL, data->context, (const gchar * const *) object_paths->pdata);

        g_ptr_array_free (object_paths, TRUE);

        list_user_data_free (data);

        return FALSE;
}

static gboolean
daemon_list_cached_users (AccountsAccounts      *accounts,
                          GDBusMethodInvocation *context)
{
        Daemon *daemon = (Daemon*)accounts;
        ListUserData *data;

        data = list_user_data_new (daemon, context);

        if (daemon->priv->reload_id > 0) {
                /* reload in progress, wait a bit */
                g_idle_add (finish_list_cached_users, data);
        }
        else {
                finish_list_cached_users (data);
        }

        return TRUE;
}

static const gchar *
daemon_get_daemon_version (AccountsAccounts *object)
{
    return VERSION;
}

typedef struct {
        gchar *user_name;
        gchar *real_name;
        gint account_type;
} CreateUserData;

static void
create_data_free (gpointer data)
{
        CreateUserData *cd = data;

        g_free (cd->user_name);
        g_free (cd->real_name);
        g_free (cd);
}

static void
daemon_create_user_authorized_cb (Daemon                *daemon,
                                  User                  *dummy,
                                  GDBusMethodInvocation *context,
                                  gpointer               data)

{
        CreateUserData *cd = data;
        User *user;
        GError *error;
        const gchar *argv[9];

        if (getpwnam (cd->user_name) != NULL) {
                throw_error (context, ERROR_USER_EXISTS, "A user with name '%s' already exists", cd->user_name);

                return;
        }

        sys_log (context, "create user '%s'", cd->user_name);

        argv[0] = "/usr/sbin/useradd";
        argv[1] = "-m";
        argv[2] = "-c";
        argv[3] = cd->real_name;
        if (cd->account_type == ACCOUNT_TYPE_ADMINISTRATOR) {
                argv[4] = "-G";
                argv[5] = "wheel";
                argv[6] = "--";
                argv[7] = cd->user_name;
                argv[8] = NULL;
        }
        else if (cd->account_type == ACCOUNT_TYPE_STANDARD) {
                argv[4] = "--";
                argv[5] = cd->user_name;
                argv[6] = NULL;
        }
        else {
                throw_error (context, ERROR_FAILED, "Don't know how to add user of type %d", cd->account_type);
                return;
        }

        error = NULL;
        if (!spawn_with_login_uid (context, argv, &error)) {
                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                g_error_free (error);
                return;
        }

        user = daemon_local_find_user_by_name (daemon, cd->user_name);

        accounts_accounts_complete_create_user (NULL, context, user_local_get_object_path (user));
}

static gboolean
daemon_create_user (AccountsAccounts      *accounts,
                    GDBusMethodInvocation *context,
                    const gchar           *user_name,
                    const gchar           *real_name,
                    gint                   account_type)
{
        Daemon *daemon = (Daemon*)accounts;
        CreateUserData *data;

        data = g_new0 (CreateUserData, 1);
        data->user_name = g_strdup (user_name);
        data->real_name = g_strdup (real_name);
        data->account_type = account_type;

        daemon_local_check_auth (daemon,
                                 NULL,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 daemon_create_user_authorized_cb,
                                 context,
                                 data,
                                 (GDestroyNotify)create_data_free);

        return TRUE;
}

typedef struct {
        gint64 uid;
        gboolean remove_files;
} DeleteUserData;

static void
daemon_delete_user_authorized_cb (Daemon                *daemon,
                                  User                  *dummy,
                                  GDBusMethodInvocation *context,
                                  gpointer               data)

{
        DeleteUserData *ud = data;
        GError *error;
        gchar *filename;
        struct passwd *pwent;
        const gchar *argv[5];

        pwent = getpwuid (ud->uid);

        if (pwent == NULL) {
                throw_error (context, ERROR_USER_DOES_NOT_EXIST, "No user with uid %d found", ud->uid);

                return;
        }

        sys_log (context, "delete user '%s' (%d)", pwent->pw_name, ud->uid);

        argv[0] = "/usr/sbin/userdel";
        if (ud->remove_files) {
                argv[1] = "-r";
                argv[2] = "--";
                argv[3] = pwent->pw_name;
                argv[4] = NULL;
        }
        else {
                argv[1] = "--";
                argv[2] = pwent->pw_name;
                argv[3] = NULL;
        }

        error = NULL;
        if (!spawn_with_login_uid (context, argv, &error)) {
                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                g_error_free (error);
                return;
        }

        filename = g_build_filename (USERDIR, pwent->pw_name, NULL);
        g_remove (filename);

        g_free (filename);

        accounts_accounts_complete_delete_user (NULL, context);
}


static gboolean
daemon_delete_user (AccountsAccounts      *accounts,
                    GDBusMethodInvocation *context,
                    gint64                 uid,
                    gboolean               remove_files)
{
        Daemon *daemon = (Daemon*)accounts;
        DeleteUserData *data;

        data = g_new0 (DeleteUserData, 1);
        data->uid = uid;
        data->remove_files = remove_files;

        daemon_local_check_auth (daemon,
                                 NULL,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 daemon_delete_user_authorized_cb,
                                 context,
                                 data,
                                 (GDestroyNotify)g_free);

        return TRUE;
}

typedef struct {
        Daemon *daemon;
        User *user;
        AuthorizedCallback authorized_cb;
        GDBusMethodInvocation *context;
        gpointer data;
        GDestroyNotify destroy_notify;
} CheckAuthData;

static void
check_auth_data_free (CheckAuthData *data)
{
        g_object_unref (data->daemon);

        if (data->user)
                g_object_unref (data->user);

        if (data->destroy_notify)
                (*data->destroy_notify) (data->data);

        g_free (data);
}

static void
check_auth_cb (PolkitAuthority *authority,
               GAsyncResult    *res,
               gpointer         data)
{
        CheckAuthData *cad = data;
        PolkitAuthorizationResult *result;
        GError *error;
        gboolean is_authorized;

        is_authorized = FALSE;

        error = NULL;
        result = polkit_authority_check_authorization_finish (authority, res, &error);
        if (error) {
                throw_error (cad->context, ERROR_PERMISSION_DENIED, "Not authorized: %s", error->message);
                g_error_free (error);
        }
        else {
                if (polkit_authorization_result_get_is_authorized (result)) {
                        is_authorized = TRUE;
                }
                else if (polkit_authorization_result_get_is_challenge (result)) {
                        throw_error (cad->context, ERROR_PERMISSION_DENIED, "Authentication is required");
                }
                else {
                        throw_error (cad->context, ERROR_PERMISSION_DENIED, "Not authorized");
                }

                g_object_unref (result);
        }

        if (is_authorized) {
                (* cad->authorized_cb) (cad->daemon,
                                        cad->user,
                                        cad->context,
                                        cad->data);
        }

        check_auth_data_free (data);
}

void
daemon_local_check_auth (Daemon                *daemon,
                         User                  *user,
                         const gchar           *action_id,
                         gboolean               allow_interaction,
                         AuthorizedCallback     authorized_cb,
                         GDBusMethodInvocation *context,
                         gpointer               authorized_cb_data,
                         GDestroyNotify         destroy_notify)
{
        CheckAuthData *data;
        PolkitSubject *subject;
        PolkitCheckAuthorizationFlags flags;

        data = g_new0 (CheckAuthData, 1);
        data->daemon = g_object_ref (daemon);
        if (user)
                data->user = g_object_ref (user);
        data->context = context;
        data->authorized_cb = authorized_cb;
        data->data = authorized_cb_data;
        data->destroy_notify = destroy_notify;

        subject = polkit_system_bus_name_new (g_dbus_method_invocation_get_sender (context));

        flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;
        if (allow_interaction)
                flags |= POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION;
        polkit_authority_check_authorization (daemon->priv->authority,
                                              subject,
                                              action_id,
                                              NULL,
                                              flags,
                                              NULL,
                                              (GAsyncReadyCallback) check_auth_cb,
                                              data);

        g_object_unref (subject);
}

gboolean
load_autologin (Daemon      *daemon,
                gchar      **name,
                gboolean    *enabled,
                GError     **error)
{
        GKeyFile *keyfile;
        GError *local_error;
        gchar *string;

        keyfile = g_key_file_new ();
        if (!g_key_file_load_from_file (keyfile,
                                        PATH_GDM_CUSTOM,
                                        G_KEY_FILE_KEEP_COMMENTS,
                                        error)) {
                g_key_file_free (keyfile);
                return FALSE;
        }

        local_error = NULL;
        string = g_key_file_get_string (keyfile, "daemon", "AutomaticLoginEnable", &local_error);
        if (local_error) {
                g_propagate_error (error, local_error);
                g_key_file_free (keyfile);
                g_free (string);
                return FALSE;
        }
        if (string != NULL && (g_ascii_strcasecmp (string, "true") == 0 || strcmp (string, "1") == 0)) {
                *enabled = TRUE;
        }
        else {
                *enabled = FALSE;
        }
        g_free (string);

        *name = g_key_file_get_string (keyfile, "daemon", "AutomaticLogin", &local_error);
        if (local_error) {
                g_propagate_error (error, local_error);
                g_key_file_free (keyfile);
                return FALSE;
        }

        g_key_file_free (keyfile);

        return TRUE;
}

static gboolean
save_autologin (Daemon      *daemon,
                const gchar *name,
                gboolean     enabled,
                GError     **error)
{
        GKeyFile *keyfile;
        gchar *data;
        gboolean result;

        keyfile = g_key_file_new ();
        if (!g_key_file_load_from_file (keyfile,
                                        PATH_GDM_CUSTOM,
                                        G_KEY_FILE_KEEP_COMMENTS,
                                        error)) {
                g_key_file_free (keyfile);
                return FALSE;
        }

        g_key_file_set_string (keyfile, "daemon", "AutomaticLoginEnable", enabled ? "True" : "False");
        g_key_file_set_string (keyfile, "daemon", "AutomaticLogin", name);

        data = g_key_file_to_data (keyfile, NULL, NULL);
        result = g_file_set_contents (PATH_GDM_CUSTOM, data, -1, error);

        g_key_file_free (keyfile);
        g_free (data);

        return result;
}

gboolean
daemon_local_set_automatic_login (Daemon    *daemon,
                                  User      *user,
                                  gboolean   enabled,
                                  GError   **error)
{
        if (daemon->priv->autologin == user && enabled) {
                return TRUE;
        }

        if (daemon->priv->autologin != user && !enabled) {
                return TRUE;
        }

        if (!save_autologin (daemon, user_local_get_user_name (user), enabled, error)) {
                return FALSE;
        }

        if (daemon->priv->autologin != NULL) {
                g_object_set (daemon->priv->autologin, "automatic-login", FALSE, NULL);
                g_signal_emit_by_name (daemon->priv->autologin, "changed", 0);
                g_object_unref (daemon->priv->autologin);
                daemon->priv->autologin = NULL;
        }

        if (enabled) {
                g_object_set (user, "automatic-login", TRUE, NULL);
                g_signal_emit_by_name (user, "changed", 0);
                g_object_ref (user);
                daemon->priv->autologin = user;
        }

        return TRUE;
}

static void
get_property (GObject    *object,
              guint       prop_id,
              GValue     *value,
              GParamSpec *pspec)
{
       switch (prop_id) {
        case PROP_DAEMON_VERSION:
                g_value_set_string (value, VERSION);
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
set_property (GObject      *object,
              guint         prop_id,
              const GValue *value,
              GParamSpec   *pspec)
{
       switch (prop_id) {
        case PROP_DAEMON_VERSION:
                g_assert_not_reached ();
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
daemon_class_init (DaemonClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->finalize = daemon_finalize;
        object_class->get_property = get_property;
        object_class->set_property = set_property;

        g_type_class_add_private (klass, sizeof (DaemonPrivate));

        g_object_class_override_property (object_class,
                                          PROP_DAEMON_VERSION,
                                          "daemon-version");
}

static void
daemon_accounts_accounts_iface_init (AccountsAccountsIface *iface)
{
        iface->handle_create_user = daemon_create_user;
        iface->handle_delete_user = daemon_delete_user;
        iface->handle_find_user_by_id = daemon_find_user_by_id;
        iface->handle_find_user_by_name = daemon_find_user_by_name;
        iface->handle_list_cached_users = daemon_list_cached_users;
        iface->get_daemon_version = daemon_get_daemon_version;
}
