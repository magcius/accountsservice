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
#define PATH_NOLOGIN "/sbin/nologin"
#define PATH_FALSE "/bin/false"
#define PATH_GDM_CUSTOM "/etc/gdm/custom.conf"

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
        "mysql",
        "ftp",
        "games",
        "man",
        "at",
        NULL
};

enum {
        PROP_0,
        PROP_DAEMON_VERSION
};

struct DaemonPrivate {
        GDBusConnection *bus_connection;
        GDBusObjectManagerServer *manager;

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

typedef struct passwd * (* EntryGeneratorFunc) (GHashTable *, gpointer *);

static void daemon_act_user_manager_glue_iface_init (ActUserManagerGlueIface *iface);

G_DEFINE_TYPE_WITH_CODE (Daemon, daemon, ACT_TYPE_USER_MANAGER_GLUE_SKELETON, G_IMPLEMENT_INTERFACE (ACT_TYPE_USER_MANAGER_GLUE, daemon_act_user_manager_glue_iface_init));

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
daemon_local_user_is_excluded (Daemon *daemon, const gchar *username, const gchar *shell)
{
        int ret;

        if (g_hash_table_lookup (daemon->priv->exclusions, username)) {
                return TRUE;
        }

        ret = FALSE;

        if (shell != NULL) {
                char *basename, *nologin_basename, *false_basename;

#ifdef HAVE_GETUSERSHELL
                char *valid_shell;

                ret = TRUE;
                setusershell ();
                while ((valid_shell = getusershell ()) != NULL) {
                        if (g_strcmp0 (shell, valid_shell) != 0)
                                continue;
                        ret = FALSE;
                }
                endusershell ();
#endif

                basename = g_path_get_basename (shell);
                nologin_basename = g_path_get_basename (PATH_NOLOGIN);
                false_basename = g_path_get_basename (PATH_FALSE);

                if (shell[0] == '\0') {
                        ret = TRUE;
                } else if (g_strcmp0 (basename, nologin_basename) == 0) {
                        ret = TRUE;
                } else if (g_strcmp0 (basename, false_basename) == 0) {
                        ret = TRUE;
                }

                g_free (basename);
                g_free (nologin_basename);
                g_free (false_basename);
        }

        return ret;
}

#ifdef HAVE_UTMPX_H
static struct passwd *
entry_generator_wtmp (GHashTable *users,
                      gpointer   *state)
{
        GHashTable *login_frequency_hash;
        struct utmpx *wtmp_entry;
        GHashTableIter iter;
        gpointer key, value;
        struct passwd *pwent;

        if (*state == NULL) {
                /* First iteration */
#ifdef UTXDB_LOG
                if (setutxdb (UTXDB_LOG, NULL) != 0) {
                        return NULL;
                }
#else
                utmpxname (_PATH_WTMPX);
                setutxent ();
#endif
                *state = g_hash_table_new (g_str_hash, g_str_equal);
        }

        /* Every iteration */
        login_frequency_hash = *state;
        while ((wtmp_entry = getutxent ())) {
                if (wtmp_entry->ut_type != USER_PROCESS) {
                        continue;
                }

                if (wtmp_entry->ut_user[0] == 0) {
                        continue;
                }

                pwent = getpwnam (wtmp_entry->ut_user);
                if (pwent == NULL) {
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

                return pwent;
        }

        /* Last iteration */
        endutxent ();

        g_hash_table_iter_init (&iter, login_frequency_hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                User *user;
                guint64 frequency = (guint64) GPOINTER_TO_UINT (value);

                user = g_hash_table_lookup (users, key);
                if (user == NULL) {
                        continue;
                }

                g_object_set (user, "login-frequency", frequency, NULL);
        }

        g_hash_table_foreach (login_frequency_hash, (GHFunc) g_free, NULL);
        g_hash_table_unref (login_frequency_hash);
        *state = NULL;
        return NULL;
}
#endif /* HAVE_UTMPX_H */

static struct passwd *
entry_generator_fgetpwent (GHashTable *users,
                           gpointer   *state)
{
        struct passwd *pwent;
        FILE *fp;

        /* First iteration */
        if (*state == NULL) {
                *state = fp = fopen (PATH_PASSWD, "r");
                if (fp == NULL) {
                        g_warning ("Unable to open %s: %s", PATH_PASSWD, g_strerror (errno));
                        return NULL;
                }
        }

        /* Every iteration */
        fp = *state;
        pwent = fgetpwent (fp);
        if (pwent != NULL) {
                return pwent;
        }

        /* Last iteration */
        fclose (fp);
        *state = NULL;
        return NULL;
}

static struct passwd *
entry_generator_cachedir (GHashTable *users,
                          gpointer   *state)
{
        struct passwd *pwent;
        const gchar *name;
        GError *error = NULL;
        gchar *filename;
        gboolean regular;
        GHashTableIter iter;
        GKeyFile *key_file;
        User *user;
        GDir *dir;

        /* First iteration */
        if (*state == NULL) {
                *state = dir = g_dir_open (USERDIR, 0, &error);
                if (error != NULL) {
                        if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
                                g_warning ("couldn't list user cache directory: %s", USERDIR);
                        g_error_free (error);
                        return NULL;
                }
        }

        /* Every iteration */

        /*
         * Use names of files of regular type to lookup information
         * about each user. Loop until we find something valid.
         */
        dir = *state;
        while (TRUE) {
                name = g_dir_read_name (dir);
                if (name == NULL)
                        break;

                /* Only load files in this directory */
                filename = g_build_filename (USERDIR, name, NULL);
                regular = g_file_test (filename, G_FILE_TEST_IS_REGULAR);
                g_free (filename);

                if (regular) {
                        pwent = getpwnam (name);
                        if (pwent == NULL)
                                g_debug ("user '%s' in cache dir but not presen on system", name);
                        else
                                return pwent;
                }
        }

        /* Last iteration */
        g_dir_close (dir);

        /* Update all the users from the files in the cache dir */
        g_hash_table_iter_init (&iter, users);
        while (g_hash_table_iter_next (&iter, (gpointer *)&name, (gpointer *)&user)) {
                filename = g_build_filename (USERDIR, name, NULL);
                key_file = g_key_file_new ();
                if (g_key_file_load_from_file (key_file, filename, 0, NULL))
                        user_local_update_from_keyfile (user, key_file);
                g_key_file_free (key_file);
                g_free (filename);
        }

        *state = NULL;
        return NULL;
}

static void
load_entries (Daemon             *daemon,
              GHashTable         *users,
              EntryGeneratorFunc  entry_generator)
{
        gpointer generator_state = NULL;
        struct passwd *pwent;
        User *user = NULL;

        g_assert (entry_generator != NULL);

        for (;;) {
                pwent = entry_generator (users, &generator_state);
                if (pwent == NULL)
                        break;

                /* Skip system users... */
                if (daemon_local_user_is_excluded (daemon, pwent->pw_name, pwent->pw_shell)) {
                        g_debug ("skipping user: %s", pwent->pw_name);
                        continue;
                }

                /* ignore duplicate entries */
                if (g_hash_table_lookup (users, pwent->pw_name)) {
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

                g_hash_table_insert (users, g_strdup (user_local_get_user_name (user)), user);
                g_debug ("loaded user: %s", user_local_get_user_name (user));
        }

        /* Generator should have cleaned up */
        g_assert (generator_state == NULL);
}

static GHashTable *
create_users_hash_table (void)
{
        return g_hash_table_new_full (g_str_hash,
                                      g_str_equal,
                                      g_free,
                                      g_object_unref);
}

static char *
create_object_path (User *user)
{
        return g_strdup_printf ("/org/freedesktop/Accounts/User%ld",
                                (long) user_local_get_uid (user));
}

static void
export_user (Daemon *daemon, User *user)
{
        ActObjectSkeleton *object;
        char *object_path = create_object_path (user);

        object = act_object_skeleton_new (object_path);
        act_object_skeleton_set_user (object, ACT_USER (user));
        g_dbus_object_manager_server_export (daemon->priv->manager,
                                             G_DBUS_OBJECT_SKELETON (object));
        g_free (object_path);
}

static void
unexport_user (Daemon *daemon, User *user)
{
        char *object_path = create_object_path (user);
        g_dbus_object_manager_server_unexport (daemon->priv->manager,
                                               object_path);
        g_free (object_path);
}

static void
reload_users (Daemon *daemon)
{
        GHashTable *users;
        GHashTable *old_users;
        GHashTableIter iter;
        gpointer name;
        User *user;

        /* Track the users that we saw during our (re)load */
        users = create_users_hash_table ();

        /* Load data from all the sources, and freeze notifies */
        load_entries (daemon, users, entry_generator_fgetpwent);
#ifdef HAVE_UTMPX_H
        load_entries (daemon, users, entry_generator_wtmp);
#endif
        load_entries (daemon, users, entry_generator_cachedir);

        /* Swap out the users */
        old_users = daemon->priv->users;
        daemon->priv->users = users;

        /* Remove all the old users */
        g_hash_table_iter_init (&iter, old_users);
        while (g_hash_table_iter_next (&iter, &name, (gpointer *)&user)) {
                if (!g_hash_table_lookup (users, name)) {
                        unexport_user (daemon, user);
                }
        }

        /* Register all the new users */
        g_hash_table_iter_init (&iter, users);
        while (g_hash_table_iter_next (&iter, &name, (gpointer *)&user)) {
                if (!g_hash_table_lookup (old_users, name)) {
                        export_user (daemon, user);
                }
                g_object_thaw_notify (G_OBJECT (user));
        }

        g_hash_table_destroy (old_users);
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

        daemon->priv->users = create_users_hash_table ();

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

        if (daemon->priv->manager != NULL)
                g_object_unref (daemon->priv->manager);

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

        daemon->priv->manager = g_dbus_object_manager_server_new ("/org/freedesktop/Accounts");

        if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (daemon),
                                               daemon->priv->bus_connection,
                                               "/org/freedesktop/Accounts/Manager",
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
        export_user (daemon, user);

        g_hash_table_insert (daemon->priv->users,
                             g_strdup (user_local_get_user_name (user)),
                             user);

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
daemon_find_user_by_id (ActUserManagerGlue      *accounts,
                        GDBusMethodInvocation *context,
                        gint64                 uid)
{
        Daemon *daemon = (Daemon*)accounts;
        User *user;

        user = daemon_local_find_user_by_id (daemon, uid);

        if (user) {
                act_user_manager_glue_complete_find_user_by_id (NULL, context, user_local_get_object_path (user));
        }
        else {
                throw_error (context, ERROR_FAILED, "Failed to look up user with uid %d.", (int)uid);
        }

        return TRUE;
}

static gboolean
daemon_find_user_by_name (ActUserManagerGlue      *accounts,
                          GDBusMethodInvocation *context,
                          const gchar           *name)
{
        Daemon *daemon = (Daemon*)accounts;
        User *user;

        user = daemon_local_find_user_by_name (daemon, name);

        if (user) {
                act_user_manager_glue_complete_find_user_by_name (NULL, context, user_local_get_object_path (user));
        }
        else {
                throw_error (context, ERROR_FAILED, "Failed to look up user with name %s.", name);
        }

        return TRUE;
}

static const gchar *
daemon_get_daemon_version (ActUserManagerGlue *object)
{
    return VERSION;
}

typedef struct {
        gchar *user_name;
        gchar *real_name;
        gint account_type;
        guint uid;
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
        const gchar *argv[11];
        gchar *uid_s = NULL;

        if (getpwnam (cd->user_name) != NULL) {
                throw_error (context, ERROR_USER_EXISTS, "A user with name '%s' already exists", cd->user_name);

                return;
        }

        sys_log (context, "create user '%s'", cd->user_name);

        argv[0] = "/usr/sbin/useradd";
        argv[1] = "-m";
        argv[2] = "-c";
        argv[3] = cd->real_name;
        if (cd->uid != 0) {
                uid_s = g_strdup_printf("%i", cd->uid);
                argv[4] = "-u";
                argv[5] = uid_s;
        }
        else {
                argv[4] = "";
                argv[5] = "";
        }
        if (cd->account_type == ACCOUNT_TYPE_ADMINISTRATOR) {
                argv[6] = "-G";
                argv[7] = "wheel";
                argv[8] = "--";
                argv[9] = cd->user_name;
                argv[10] = NULL;
        }
        else if (cd->account_type == ACCOUNT_TYPE_STANDARD) {
                argv[6] = "--";
                argv[7] = cd->user_name;
                argv[8] = NULL;
        }
        else {
                if (uid_s != NULL)
                        g_free(uid_s);
                throw_error (context, ERROR_FAILED, "Don't know how to add user of type %d", cd->account_type);
                return;
        }

        error = NULL;
        if (!spawn_with_login_uid (context, argv, &error)) {
                if (uid_s != NULL)
                        g_free(uid_s);
                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                g_error_free (error);
                return;
        }
        if (uid_s != NULL)
                g_free(uid_s);

        user = daemon_local_find_user_by_name (daemon, cd->user_name);

        act_user_manager_glue_complete_create_user (NULL, context, user_local_get_object_path (user));
}

static gboolean
daemon_create_user_ex (ActUserManagerGlue      *accounts,
                       GDBusMethodInvocation *context,
                       const gchar           *user_name,
                       const gchar           *real_name,
                       gint                   account_type,
                       uid_t                  uid)
{
        Daemon *daemon = (Daemon*)accounts;
        CreateUserData *data;

        data = g_new0 (CreateUserData, 1);
        data->user_name = g_strdup (user_name);
        data->real_name = g_strdup (real_name);
        data->account_type = account_type;
        data->uid = uid;

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

static gboolean
daemon_create_user (ActUserManagerGlue      *accounts,
                    GDBusMethodInvocation *context,
                    const gchar           *user_name,
                    const gchar           *real_name,
                    gint                   account_type)
{
        return daemon_create_user_ex(accounts, context, user_name, real_name, account_type, 0);
}

static void
daemon_cache_user_authorized_cb (Daemon                *daemon,
                                 User                  *dummy,
                                 GDBusMethodInvocation *context,
                                 gpointer               data)
{
        const gchar *user_name = data;
        GError      *error = NULL;
        gchar       *filename;
        gchar       *comment;
        User        *user;

        sys_log (context, "cache user '%s'", user_name);

        user = daemon_local_find_user_by_name (daemon, user_name);
        if (user == NULL) {
                throw_error (context, ERROR_USER_DOES_NOT_EXIST,
                             "No user with the name %s found", user_name);
                return;
        }

        /* Always use the canonical user name looked up */
        user_name = user_local_get_user_name (user);

        filename = g_build_filename (USERDIR, user_name, NULL);
        if (!g_file_test (filename, G_FILE_TEST_EXISTS)) {
                comment = g_strdup_printf ("# Cached file for %s\n\n", user_name);
                g_file_set_contents (filename, comment, -1, &error);
                g_free (comment);

                if (error != NULL) {
                        g_warning ("Couldn't write user cache file: %s: %s",
                                   filename, error->message);
                        g_error_free (error);
                }
        }

        g_free (filename);

        act_user_manager_glue_complete_cache_user (NULL, context, user_local_get_object_path (user));
}

static gboolean
daemon_cache_user (ActUserManagerGlue      *accounts,
                   GDBusMethodInvocation *context,
                   const gchar           *user_name)
{
        Daemon *daemon = (Daemon*)accounts;

        /* Can't have a slash in the user name */
        if (strchr (user_name, '/') != NULL) {
                g_dbus_method_invocation_return_error (context, G_DBUS_ERROR,
                                                       G_DBUS_ERROR_INVALID_ARGS,
                                                       "Invalid user name: %s", user_name);
                return TRUE;
        }

        daemon_local_check_auth (daemon,
                                 NULL,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 daemon_cache_user_authorized_cb,
                                 context,
                                 g_strdup (user_name),
                                 g_free);

        return TRUE;
}

static void
daemon_uncache_user_authorized_cb (Daemon                *daemon,
                                   User                  *dummy,
                                   GDBusMethodInvocation *context,
                                   gpointer               data)
{
        const gchar *user_name = data;
        gchar       *filename;
        User        *user;

        sys_log (context, "uncache user '%s'", user_name);

        user = daemon_local_find_user_by_name (daemon, user_name);
        if (user == NULL) {
                throw_error (context, ERROR_USER_DOES_NOT_EXIST,
                             "No user with the name %s found", user_name);
                return;
        }

        /* Always use the canonical user name looked up */
        user_name = user_local_get_user_name (user);

        filename = g_build_filename (USERDIR, user_name, NULL);
        g_remove (filename);
        g_free (filename);

        filename = g_build_filename (ICONDIR, user_name, NULL);
        g_remove (filename);
        g_free (filename);

        act_user_manager_glue_complete_uncache_user (NULL, context);

        queue_reload_users (daemon);
}

static gboolean
daemon_uncache_user (ActUserManagerGlue      *accounts,
                     GDBusMethodInvocation *context,
                     const gchar           *user_name)
{
        Daemon *daemon = (Daemon*)accounts;

        daemon_local_check_auth (daemon,
                                 NULL,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 daemon_uncache_user_authorized_cb,
                                 context,
                                 g_strdup (user_name),
                                 g_free);

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
        const gchar *argv[6];

        pwent = getpwuid (ud->uid);

        if (pwent == NULL) {
                throw_error (context, ERROR_USER_DOES_NOT_EXIST, "No user with uid %d found", ud->uid);

                return;
        }

        sys_log (context, "delete user '%s' (%d)", pwent->pw_name, ud->uid);

        filename = g_build_filename (USERDIR, pwent->pw_name, NULL);
        g_remove (filename);
        g_free (filename);

        filename = g_build_filename (ICONDIR, pwent->pw_name, NULL);
        g_remove (filename);
        g_free (filename);

        argv[0] = "/usr/sbin/userdel";
        if (ud->remove_files) {
                argv[1] = "-f";
                argv[2] = "-r";
                argv[3] = "--";
                argv[4] = pwent->pw_name;
                argv[5] = NULL;
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

        act_user_manager_glue_complete_delete_user (NULL, context);
}


static gboolean
daemon_delete_user (ActUserManagerGlue      *accounts,
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
daemon_act_user_manager_glue_iface_init (ActUserManagerGlueIface *iface)
{
        iface->handle_create_user = daemon_create_user;
        iface->handle_create_user_ex = daemon_create_user_ex;
        iface->handle_delete_user = daemon_delete_user;
        iface->handle_find_user_by_id = daemon_find_user_by_id;
        iface->handle_find_user_by_name = daemon_find_user_by_name;
        iface->get_daemon_version = daemon_get_daemon_version;
        iface->handle_cache_user = daemon_cache_user;
        iface->handle_uncache_user = daemon_uncache_user;
}
