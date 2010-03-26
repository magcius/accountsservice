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

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <polkit/polkit.h>

#include "daemon.h"
#include "daemon-glue.h"
#include "util.h"

#define PATH_PASSWD "/etc/passwd"
#define PATH_SHADOW "/etc/shadow"
#define MINIMAL_UID 500

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

enum {
        USER_ADDED,
        USER_REMOVED,
        USER_CHANGED,
        LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct DaemonPrivate {
        DBusGConnection *bus_connection;
        DBusGProxy *bus_proxy;

        GHashTable *users;
        GHashTable *exclusions;

        User *autologin;

        GFileMonitor *passwd_monitor;
        GFileMonitor *shadow_monitor;

        guint reload_id;
        guint ck_history_id;
        guint autologin_id;

        PolkitAuthority *authority;
};

static void daemon_finalize   (GObject     *object);

G_DEFINE_TYPE (Daemon, daemon, G_TYPE_OBJECT)

#define DAEMON_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), TYPE_DAEMON, DaemonPrivate))

GQuark
error_quark (void)
{
  static GQuark ret = 0;

  if (ret == 0)
    {
      ret = g_quark_from_static_string ("accounts_error");
    }

  return ret;
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
daemon_class_init (DaemonClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->finalize = daemon_finalize;
        object_class->get_property = get_property;

        g_type_class_add_private (klass, sizeof (DaemonPrivate));

        signals[USER_ADDED] = g_signal_new ("user-added",
                                            G_OBJECT_CLASS_TYPE (klass),
                                            G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
                                            0,
                                            NULL,
                                            NULL,
                                            g_cclosure_marshal_VOID__BOXED,
                                            G_TYPE_NONE,
                                            1,
                                            DBUS_TYPE_G_OBJECT_PATH);

        signals[USER_REMOVED] = g_signal_new ("user-deleted",
                                              G_OBJECT_CLASS_TYPE (klass),
                                              G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
                                              0,
                                              NULL,
                                              NULL,
                                              g_cclosure_marshal_VOID__BOXED,
                                              G_TYPE_NONE,
                                              1,
                                              DBUS_TYPE_G_OBJECT_PATH);

        signals[USER_CHANGED] = g_signal_new ("user-changed",
                                              G_OBJECT_CLASS_TYPE (klass),
                                              G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
                                              0,
                                              NULL,
                                              NULL,
                                              g_cclosure_marshal_VOID__BOXED,
                                              G_TYPE_NONE,
                                              1,
                                              DBUS_TYPE_G_OBJECT_PATH);

        dbus_g_object_type_install_info (TYPE_DAEMON,
                                         &dbus_glib_daemon_object_info);

        dbus_g_error_domain_register (ERROR,
                                      "org.freedesktop.Accounts.Error",
                                      TYPE_ERROR);

        g_object_class_install_property (object_class,
                                         PROP_DAEMON_VERSION,
                                         g_param_spec_string ("daemon-version",
                                                              "Daemon version",
                                                              "Daemon version",
                                                              NULL,
                                                              G_PARAM_READABLE));
}


static void
listify_hash_values_hfunc (gpointer key,
                           gpointer value,
                           gpointer user_data)
{
        GSList **list = user_data;

        *list = g_slist_prepend (*list, value);
}

static gboolean
parse_value_as_ulong (const gchar *value,
                      gulong      *ulongval)
{
        gchar *end_of_valid_long;
        glong long_value;
        gulong ulong_value;

        errno = 0;
        long_value = strtol (value, &end_of_valid_long, 10);

        if (*value == '\0' || *end_of_valid_long != '\0') {
                return FALSE;
        }

        ulong_value = long_value;
        if (ulong_value != long_value || errno == ERANGE) {
                return FALSE;
        }

        *ulongval = ulong_value;

        return TRUE;
}

static gboolean
parse_ck_history_line (const gchar  *line,
                       gchar       **user_namep,
                       gulong       *frequencyp)
{
        GRegex *re;
        GMatchInfo *match_info;
        gboolean res;
        gboolean ret;
        GError *error;

        ret = FALSE;
        re = NULL;
        match_info = NULL;

        error = NULL;
        re = g_regex_new ("(?P<username>[0-9a-zA-Z]+)[ ]+(?P<frequency>[0-9]+)", 0, 0, &error);
        if (re == NULL) {
                if (error != NULL) {
                        g_critical ("%s", error->message);
                } else {
                       g_critical ("Error in regex call");
                }
                goto out;
        }

        g_regex_match (re, line, 0, &match_info);

        res = g_match_info_matches (match_info);
        if (! res) {
                g_warning ("Unable to parse history: %s", line);
                goto out;
        }

        if (user_namep != NULL) {
                *user_namep = g_match_info_fetch_named (match_info, "username");
        }

        if (frequencyp != NULL) {
                char *freq;
                freq = g_match_info_fetch_named (match_info, "frequency");
                res = parse_value_as_ulong (freq, frequencyp);
                g_free (freq);
                if (! res) {
                        goto out;
                }
        }

        ret = TRUE;

 out:
        if (match_info != NULL) {
                g_match_info_free (match_info);
        }
        if (re != NULL) {
                g_regex_unref (re);
        }
        return ret;
}

static void
process_ck_history_line (Daemon      *daemon,
                         const gchar *line)
{
        gboolean res;
        gchar *username;
        gulong frequency;
        User *user;

        frequency = 0;
        username = NULL;
        res = parse_ck_history_line (line, &username, &frequency);
        if (! res) {
                return;
        }

        if (g_hash_table_lookup (daemon->priv->exclusions, username)) {
                g_debug ("excluding user '%s'", username);
                g_free (username);
                return;
        }

        user = daemon_local_find_user_by_name (daemon, username);
        if (user == NULL) {
                g_debug ("unable to lookup user '%s'", username);
                g_free (username);
                return;
        }

        g_object_set (user, "login-frequency", (guint64) frequency, NULL);
        g_free (username);
}

static gboolean
ck_history_watch (GIOChannel   *source,
                  GIOCondition  condition,
                  Daemon       *daemon)
{
        GIOStatus status;
        gboolean done = FALSE;

        if (condition & G_IO_IN) {
                gchar   *str;
                GError *error;

                error = NULL;
                status = g_io_channel_read_line (source, &str, NULL, NULL, &error);
                if (error != NULL) {
                        g_warning ("unable to read line: %s", error->message);
                        g_error_free (error);
                }
                if (status == G_IO_STATUS_NORMAL) {
                        g_debug ("history output: %s", str);
                        process_ck_history_line (daemon, str);
                } else if (status == G_IO_STATUS_EOF) {
                        done = TRUE;
                }

                g_free (str);
        } else if (condition & G_IO_HUP) {
                done = TRUE;
        }

        if (done) {
                daemon->priv->ck_history_id = 0;
                return FALSE;
        }

        return TRUE;
}

static void
reload_ck_history (Daemon *daemon)
{
        gchar *command;
        GError *error;
        gboolean res;
        gchar **argv;
        gint standard_out;
        GIOChannel *channel;

        command = g_strdup ("ck-history --frequent --session-type=''");
        g_debug ("running '%s'", command);
        error = NULL;
        if (! g_shell_parse_argv (command, NULL, &argv, &error)) {
                if (error != NULL) {
                        g_warning ("Could not parse command: %s", error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Could not parse command");
                }
                goto out;
        }

        error = NULL;
        res = g_spawn_async_with_pipes (NULL,
                                        argv,
                                        NULL,
                                        G_SPAWN_SEARCH_PATH,
                                        NULL,
                                        NULL,
                                        NULL, /* pid */
                                        NULL,
                                        &standard_out,
                                        NULL,
                                        &error);
        g_strfreev (argv);
        if (! res) {
                if (error != NULL) {
                        g_warning ("Unable to run ck-history: %s", error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Unable to run ck-history");
                }
                goto out;
        }

        channel = g_io_channel_unix_new (standard_out);
        g_io_channel_set_close_on_unref (channel, TRUE);
        g_io_channel_set_flags (channel,
                                g_io_channel_get_flags (channel) | G_IO_FLAG_NONBLOCK,
                                NULL);
        daemon->priv->ck_history_id = g_io_add_watch (channel,
                                                       G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
                                                       (GIOFunc)ck_history_watch,
                                                       daemon);
        g_io_channel_unref (channel);

 out:
        g_free (command);
}

static void
reload_passwd (Daemon *daemon)
{
        struct passwd *pwent;
        GSList *old_users;
        GSList *new_users;
        GSList *list;
        FILE *fp;
        User *user = NULL;

        old_users = NULL;
        new_users = NULL;

        errno = 0;
        fp = fopen (PATH_PASSWD, "r");
        if (fp == NULL) {
                g_warning ("Unable to open %s: %s", PATH_PASSWD, g_strerror (errno));
                goto out;
        }
        g_hash_table_foreach (daemon->priv->users, listify_hash_values_hfunc, &old_users);
        g_slist_foreach (old_users, (GFunc) g_object_ref, NULL);

        for (pwent = fgetpwent (fp); pwent != NULL; pwent = fgetpwent (fp)) {
                /* Skip users below MINIMAL_UID... */
                if (pwent->pw_uid < MINIMAL_UID) {
                        continue;
                }

                /* ...and explicitly excluded users */
                if (g_hash_table_lookup (daemon->priv->exclusions, pwent->pw_name)) {
                        g_debug ("explicitly skipping user: %s", pwent->pw_name);
                        continue;
                }

                user = g_hash_table_lookup (daemon->priv->users, pwent->pw_name);

                /* Update users already in the *new* list */
                if (g_slist_find (new_users, user)) {
                        user_local_update_from_pwent (user, pwent);
                        continue;
                }

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
                        g_signal_emit (daemon, signals[USER_REMOVED], 0, user_local_get_object_path (user));
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

                        g_signal_emit (daemon, signals[USER_ADDED], 0, user_local_get_object_path (user));
                }
        }

 out:
        /* Cleanup */

        fclose (fp);

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
        reload_ck_history (daemon);
        reload_passwd (daemon);
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
        User *user;

        daemon->priv->autologin_id = 0;

        if (!load_autologin (daemon, &name, &enabled, &error)) {
                g_warning ("failed to load gdms custom.conf: %s", error->message);
                g_error_free (error);
                g_free (name);

                return FALSE;
        }

        if (enabled) {
                g_print ("automatic login is enabled for '%s'\n", name);
                user = daemon_local_find_user_by_name (daemon, name);
                g_object_set (user, "automatic-login", TRUE, NULL);
                daemon->priv->autologin = g_object_ref (user);
        }
        else {
                g_print ("automatic login is disabled\n");
        }

        g_free (name);

        return FALSE;
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

        reload_users (daemon);
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
                dbus_g_connection_unref (daemon->priv->bus_connection);

        g_hash_table_destroy (daemon->priv->users);

        G_OBJECT_CLASS (daemon_parent_class)->finalize (object);
}

static gboolean
register_accounts_daemon (Daemon *daemon)
{
        DBusConnection *connection;
        DBusError dbus_error;
        GError *error = NULL;

        daemon->priv->authority = polkit_authority_get ();

        error = NULL;
        daemon->priv->bus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (daemon->priv->bus_connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                goto error;
        }
        connection = dbus_g_connection_get_connection (daemon->priv->bus_connection);

        dbus_g_connection_register_g_object (daemon->priv->bus_connection,
                                             "/org/freedesktop/Accounts",
                                             G_OBJECT (daemon));

        daemon->priv->bus_proxy = dbus_g_proxy_new_for_name (daemon->priv->bus_connection,
                                                             DBUS_SERVICE_DBUS,
                                                             DBUS_PATH_DBUS,
                                                             DBUS_INTERFACE_DBUS);
        dbus_error_init (&dbus_error);
        /* need to listen to NameOwnerChanged */
        dbus_bus_add_match (connection,
                            "type='signal'"
                            ",interface='"DBUS_INTERFACE_DBUS"'"
                            ",sender='"DBUS_SERVICE_DBUS"'"
                            ",member='NameOwnerChanged'",
                            &dbus_error);

        if (dbus_error_is_set (&dbus_error)) {
                g_warning ("Cannot add match rule: %s: %s", dbus_error.name, dbus_error.message);
                dbus_error_free (&dbus_error);
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
throw_error (DBusGMethodInvocation *context,
             gint                   error_code,
             const gchar           *format,
             ...)
{
        GError *error;
        va_list args;
        gchar *message;

        va_start (args, format);
        message = g_strdup_vprintf (format, args);
        va_end (args);

        error = g_error_new (ERROR, error_code, "%s", message);
        dbus_g_method_return_error (context, error);
        g_error_free (error);

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

        g_signal_emit (daemon, signals[USER_ADDED], 0, user_local_get_object_path (user));

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
                g_warning ("unable to lookup uid %d", (int)uid);
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
                g_warning ("unable to lookup name %s", name);
                return NULL;
        }

        user = g_hash_table_lookup (daemon->priv->users, pwent->pw_name);

        if (user == NULL)
                user = add_new_user_for_pwent (daemon, pwent);

        return user;
}

gboolean
daemon_find_user_by_id (Daemon                *daemon,
                        gint64                 uid,
                        DBusGMethodInvocation *context)
{
        User *user;

        user = daemon_local_find_user_by_id (daemon, uid);

        if (user) {
                dbus_g_method_return (context,
                                      user_local_get_object_path (user));
        }
        else {
                throw_error (context, ERROR_FAILED, "Failed to look up user with uid %d.", (int)uid);
        }

        return TRUE;
}

gboolean
daemon_find_user_by_name (Daemon                *daemon,
                          const gchar           *name,
                          DBusGMethodInvocation *context)
{
        User *user;

        user = daemon_local_find_user_by_name (daemon, name);

        if (user) {
                dbus_g_method_return (context,
                                      user_local_get_object_path (user));
        }
        else {
                throw_error (context, ERROR_FAILED, "Failed to look up user with name %s.", name);
        }

        return TRUE;
}

static void
enumerate_cb (gpointer key,
              gpointer value,
              gpointer user_data)
{
        User *user = USER (value);
        GPtrArray *object_paths = user_data;
        g_ptr_array_add (object_paths, g_strdup (user_local_get_object_path (user)));
}

typedef struct {
        Daemon *daemon;
        DBusGMethodInvocation *context;
} ListUserData;

static ListUserData *
list_user_data_new (Daemon                *daemon,
                    DBusGMethodInvocation *context)
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

        object_paths = g_ptr_array_new ();
        g_hash_table_foreach (data->daemon->priv->users, enumerate_cb, object_paths);

        dbus_g_method_return (data->context, object_paths);

        g_ptr_array_foreach (object_paths, (GFunc) g_free, NULL);
        g_ptr_array_free (object_paths, TRUE);

        list_user_data_free (data);

        return FALSE;
}

gboolean
daemon_list_cached_users (Daemon                *daemon,
                          DBusGMethodInvocation *context)
{
        ListUserData *data;

        data = list_user_data_new (daemon, context);

        if (daemon->priv->reload_id > 0) {
                /* reload in progress, wait */
                g_idle_add (finish_list_cached_users, data);
        }
        else {
                finish_list_cached_users (data);
        }

        return TRUE;
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
                                  DBusGMethodInvocation *context,
                                  gpointer               data)

{
        CreateUserData *cd = data;
        User *user;
        GError *error;
        gchar *argv[8];

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
                argv[5] = "desktop_admin_r";
                argv[6] = cd->user_name;
                argv[7] = NULL;
        }
        else if (cd->account_type == ACCOUNT_TYPE_STANDARD) {
                argv[4] = "-G";
                argv[5] = "desktop_user_r";
                argv[6] = cd->user_name;
                argv[7] = NULL;
        }
        else {
                argv[4] = cd->user_name;
                argv[5] = NULL;
        }

        error = NULL;
        if (!spawn_with_login_uid (context, argv, &error)) {
                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                g_error_free (error);
                return;
        }

        user = daemon_local_find_user_by_name (daemon, cd->user_name);

        dbus_g_method_return (context, user_local_get_object_path (user));
}

gboolean
daemon_create_user (Daemon                *daemon,
                    const gchar           *user_name,
                    const gchar           *real_name,
                    gint                   account_type,
                    DBusGMethodInvocation *context)
{
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
                                  DBusGMethodInvocation *context,
                                  gpointer               data)

{
        DeleteUserData *ud = data;
        GError *error;
        gchar *filename;
        struct passwd *pwent;
        gchar *argv[4];

        pwent = getpwuid (ud->uid);

        if (pwent == NULL) {
                throw_error (context, ERROR_USER_DOES_NOT_EXIST, "No user with uid %d found", ud->uid);

                return;
        }

        sys_log (context, "delete user '%s' (%d)", pwent->pw_name, ud->uid);

        argv[0] = "/usr/sbin/userdel";
        if (ud->remove_files) {
                argv[1] = "-r";
                argv[2] = pwent->pw_name;
                argv[3] = NULL;
        }
        else {
                argv[1] = pwent->pw_name;
                argv[2] = NULL;
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

        dbus_g_method_return (context);
}


gboolean
daemon_delete_user (Daemon                *daemon,
                    gint64                 uid,
                    gboolean               remove_files,
                    DBusGMethodInvocation *context)
{
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
        DBusGMethodInvocation *context;
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
                         DBusGMethodInvocation *context,
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

        subject = polkit_system_bus_name_new (dbus_g_method_get_sender (context));

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
        const gchar *filename;
        GError *local_error;
        gchar *string;

        filename = "/etc/gdm/custom.conf";

        keyfile = g_key_file_new ();
        if (!g_key_file_load_from_file (keyfile,
                                        filename,
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
        if (g_strcmp0 (string, "True") == 0) {
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
        const gchar *filename;
        gchar *data;
        gboolean result;

        filename = "/etc/gdm/custom.conf";

        keyfile = g_key_file_new ();
        if (!g_key_file_load_from_file (keyfile,
                                        filename,
                                        G_KEY_FILE_KEEP_COMMENTS,
                                        error)) {
                g_key_file_free (keyfile);
                return FALSE;
        }

        g_key_file_set_string (keyfile, "daemon", "AutomaticLoginEnable", enabled ? "True" : "False");
        g_key_file_set_string (keyfile, "daemon", "AutomaticLogin", name);

        data = g_key_file_to_data (keyfile, NULL, NULL);
        result = g_file_set_contents (filename, data, -1, error);

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

        if (!save_autologin (daemon, user_local_get_user_name (user), enabled, error)) {
                return FALSE;
        }

        if (daemon->priv->autologin != NULL) {
                g_object_set (daemon->priv->autologin, "automatic-login", FALSE, NULL);
                g_signal_emit_by_name (daemon->priv->autologin, "changed", 0);
                g_object_unref (daemon->priv->autologin);
        }

        if (enabled) {
                g_object_ref (user);
                g_object_set (daemon->priv->autologin, "automatic-login", TRUE, NULL);
                daemon->priv->autologin = user;
                g_signal_emit_by_name (daemon->priv->autologin, "changed", 0);
        }

        return TRUE;
}

