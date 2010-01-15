/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
  *
  * Copyright (C) 2004-2005 James M. Cape <jcape@ignore-your.tv>.
  * Copyright (C) 2007-2008 William Jon McCann <mccann@jhu.edu>
  * Copyright (C) 2009-2010 Red Hat, Inc.
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

#define _BSD_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <glib/gstdio.h>

#include <gdk-pixbuf/gdk-pixbuf.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "daemon.h"
#include "user.h"
#include "user-glue.h"

enum {
        PROP_0,
        PROP_UID,
        PROP_USER_NAME,
        PROP_REAL_NAME,
        PROP_HOME_DIR,
        PROP_SHELL,
        PROP_ACCOUNT_TYPE,
        PROP_EMAIL,
        PROP_LANGUAGE,
        PROP_LOCATION,
        PROP_PASSWORD_MODE,
        PROP_PASSWORD_HINT,
        PROP_LOGIN_FREQUENCY,
        PROP_ICON_FILE,
        PROP_LOCKED
};

enum {
        CHANGED,
        LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct User {
        GObject       parent;

        DBusGConnection *system_bus_connection;
        gchar *object_path;

        Daemon       *daemon;

        uid_t         uid;
        gid_t         gid;
        gchar        *user_name;
        gchar        *real_name;
        AccountType   account_type;
        PasswordMode  password_mode;
        gchar        *password_hint;
        gchar        *home_dir;
        gchar        *shell;
        gchar        *email;
        gchar        *language;
        gchar        *location;
        guint64       login_frequency;
        gchar        *icon_file;
        gboolean      locked;
};

typedef struct UserClass
{
        GObjectClass parent_class;
} UserClass;

static void user_finalize (GObject *object);

G_DEFINE_TYPE (User, user, G_TYPE_OBJECT)

static void
user_set_property (GObject      *object,
                   guint         param_id,
                   const GValue *value,
                   GParamSpec   *pspec)
{
        User *user = USER (object);

        switch (param_id) {
        case PROP_ACCOUNT_TYPE:
                user->account_type = g_value_get_int (value);
                break;
        case PROP_LANGUAGE:
                user->language = g_value_dup_string (value);
                break;
        case PROP_EMAIL:
                user->email = g_value_dup_string (value);
                break;
        case PROP_LOGIN_FREQUENCY:
                user->login_frequency = g_value_get_uint64 (value);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
                break;
        }
}

static void
user_get_property (GObject    *object,
                   guint       param_id,
                   GValue     *value,
                   GParamSpec *pspec)
{
        User *user = USER (object);

        switch (param_id) {
        case PROP_UID:
                g_value_set_uint64 (value, user->uid);
                break;
        case PROP_USER_NAME:
                g_value_set_string (value, user->user_name);
                break;
        case PROP_REAL_NAME:
                g_value_set_string (value, user->real_name);
                break;
        case PROP_ACCOUNT_TYPE:
                g_value_set_int (value, user->account_type);
                break;
        case PROP_PASSWORD_MODE:
                g_value_set_int (value, user->password_mode);
                break;
        case PROP_PASSWORD_HINT:
                g_value_set_string (value, user->password_hint);
                break;
        case PROP_HOME_DIR:
                g_value_set_string (value, user->home_dir);
                break;
        case PROP_SHELL:
                g_value_set_string (value, user->shell);
                break;
        case PROP_EMAIL:
                g_value_set_string (value, user->email);
                break;
        case PROP_LANGUAGE:
                g_value_set_string (value, user->language);
                break;
        case PROP_LOCATION:
                g_value_set_string (value, user->location);
                break;
        case PROP_ICON_FILE:
                g_value_set_string (value, user->icon_file);
                break;
        case PROP_LOGIN_FREQUENCY:
                g_value_set_uint64 (value, user->login_frequency);
                break;
        case PROP_LOCKED:
                g_value_set_boolean (value, user->locked);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, param_id, pspec);
                break;
        }
}

static void
user_class_init (UserClass *class)
{
        GObjectClass *gobject_class;

        gobject_class = G_OBJECT_CLASS (class);

        gobject_class->get_property = user_get_property;
        gobject_class->set_property = user_set_property;
        gobject_class->finalize = user_finalize;

        dbus_g_object_type_install_info (TYPE_USER,
                                         &dbus_glib_user_object_info);

        signals[CHANGED] = g_signal_new ("changed",
                                         G_OBJECT_CLASS_TYPE (class),
                                         G_SIGNAL_RUN_LAST,
                                         0,
                                         NULL,
                                         NULL,
                                         g_cclosure_marshal_VOID__VOID,
                                         G_TYPE_NONE,
                                         0);

        g_object_class_install_property (gobject_class,
                                         PROP_REAL_NAME,
                                         g_param_spec_string ("real-name",
                                                              "Real Name",
                                                              "The real name to display for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));

        g_object_class_install_property (gobject_class,
                                         PROP_ACCOUNT_TYPE,
                                         g_param_spec_int ("account-type",
                                                           "Account Type",
                                                           "The account type for this user.",
                                                           0, ACCOUNT_TYPE_LAST,
                                                           0,
                                                           G_PARAM_READWRITE));

        g_object_class_install_property (gobject_class,
                                         PROP_PASSWORD_MODE,
                                         g_param_spec_int ("password-mode",
                                                           "Password Mode",
                                                           "The password mode for this user.",
                                                           0, PASSWORD_MODE_LAST,
                                                           PASSWORD_MODE_REGULAR,
                                                           G_PARAM_READABLE));

        g_object_class_install_property (gobject_class,
                                         PROP_PASSWORD_HINT,
                                         g_param_spec_string ("password-hint",
                                                              "Password Hint",
                                                              "Hint to help this user remember his password",
                                                              NULL,
                                                              G_PARAM_READABLE));

        g_object_class_install_property (gobject_class,
                                         PROP_UID,
                                         g_param_spec_uint64 ("uid",
                                                              "User ID",
                                                              "The UID for this user.",
                                                              0, G_MAXUINT64, 0,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_USER_NAME,
                                         g_param_spec_string ("user-name",
                                                              "User Name",
                                                              "The login name for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));

        g_object_class_install_property (gobject_class,
                                         PROP_HOME_DIR,
                                         g_param_spec_string ("home-directory",
                                                              "Home Directory",
                                                              "The home directory for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_SHELL,
                                         g_param_spec_string ("shell",
                                                              "Shell",
                                                              "The shell for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_EMAIL,
                                         g_param_spec_string ("email",
                                                              "Email",
                                                              "The email address for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_LANGUAGE,
                                         g_param_spec_string ("language",
                                                              "Language",
                                                              "The language for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_LOCATION,
                                         g_param_spec_string ("location",
                                                              "Location",
                                                              "The location of this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_LOGIN_FREQUENCY,
                                         g_param_spec_uint64 ("login-frequency",
                                                              "login frequency",
                                                              "login frequency",
                                                              0,
                                                              G_MAXUINT64,
                                                              0,
                                                              G_PARAM_READWRITE));
        g_object_class_install_property (gobject_class,
                                         PROP_ICON_FILE,
                                         g_param_spec_string ("icon-file",
                                                              "Icon file",
                                                              "The icon file to use for this user.",
                                                              NULL,
                                                              G_PARAM_READABLE));

        g_object_class_install_property (gobject_class,
                                         PROP_LOCKED,
                                         g_param_spec_boolean ("locked",
                                                               "Locked",
                                                               "Locked",
                                                               FALSE,
                                                              G_PARAM_READABLE));

}


static void
user_init (User *user)
{
        user->system_bus_connection = NULL;
        user->object_path = NULL;
        user->user_name = NULL;
        user->real_name = NULL;
        user->account_type = ACCOUNT_TYPE_STANDARD;
        user->home_dir = NULL;
        user->shell = NULL;
        user->icon_file = NULL;
        user->email = NULL;
        user->language = NULL;
        user->location = NULL;
        user->password_mode = PASSWORD_MODE_REGULAR;
        user->password_hint = NULL;
        user->locked = FALSE;
}

static void
user_finalize (GObject *object)
{
        User *user;

        user = USER (object);

        g_free (user->object_path);
        g_free (user->user_name);
        g_free (user->real_name);
        g_free (user->home_dir);
        g_free (user->shell);
        g_free (user->icon_file);
        g_free (user->email);
        g_free (user->language);
        g_free (user->location);
        g_free (user->password_hint);

        if (G_OBJECT_CLASS (user_parent_class)->finalize)
                (*G_OBJECT_CLASS (user_parent_class)->finalize) (object);
}

static gint
account_type_from_groups (struct passwd *pwent)
{
        struct group *grp;
        gid_t desktop_user_r;
        gid_t desktop_admin_r;
        gid_t groups[20];
        gint n_groups = 20;
        gint i;

        grp = getgrnam ("desktop_user_r");
        if (grp == NULL) {
                g_warning ("desktop_user_r group not found");
                return ACCOUNT_TYPE_STANDARD;
        }
        desktop_user_r = grp->gr_gid;

        grp = getgrnam ("desktop_admin_r");
        if (grp == NULL) {
                g_warning ("desktop_admin_r group not found");
                return ACCOUNT_TYPE_STANDARD;
        }
        desktop_admin_r = grp->gr_gid;

        if (getgrouplist (pwent->pw_name, pwent->pw_gid, groups, &n_groups) == -1) {
                g_warning ("too many groups");
                return ACCOUNT_TYPE_STANDARD;
        }

        for (i = 0; i < n_groups; i++) {
                if (groups[i] == desktop_user_r)
                        return ACCOUNT_TYPE_STANDARD;
                if (groups[i] == desktop_admin_r)
                        return ACCOUNT_TYPE_ADMINISTRATOR;
        }

        return ACCOUNT_TYPE_SUPERVISED;
}

void
user_local_update_from_pwent (User          *user,
                              struct passwd *pwent)
{
        gchar *real_name;
        g_object_freeze_notify (G_OBJECT (user));

        if (pwent->pw_gecos && pwent->pw_gecos[0] != '\0') {
                gchar *first_comma = NULL;
                gchar *valid_utf8_name = NULL;

                if (g_utf8_validate (pwent->pw_gecos, -1, NULL)) {
                        valid_utf8_name = pwent->pw_gecos;
                        first_comma = g_utf8_strchr (valid_utf8_name, -1, ',');
                } else {
                        g_warning ("User %s has invalid UTF-8 in GECOS field. "
                                   "It would be a good thing to check /etc/passwd.",
                                   pwent->pw_name ? pwent->pw_name : "");
                }

                if (first_comma) {
                        real_name = g_strndup (valid_utf8_name,
                                                  (first_comma - valid_utf8_name));
                } else if (valid_utf8_name) {
                        real_name = g_strdup (valid_utf8_name);
                } else {
                        real_name = NULL;
                }

                if (real_name && real_name[0] == '\0') {
                        g_free (real_name);
                        real_name = NULL;
                }
        } else {
                real_name = NULL;
        }
        if ((real_name && !user->real_name) ||
            (!real_name && user->real_name) ||
            (real_name && user->real_name &&
             strcmp (real_name, user->real_name) != 0)) {
                g_free (user->real_name);
                user->real_name = real_name;
                g_object_notify (G_OBJECT (user), "real-name");
        } else {
                g_free (real_name);
        }

        /* UID */
        if (pwent->pw_uid != user->uid) {
                user->uid = pwent->pw_uid;
                g_object_notify (G_OBJECT (user), "uid");
        }

        /* GID */
        user->gid = pwent->pw_gid;

        user->account_type = account_type_from_groups (pwent);

        /* Username */
        if ((pwent->pw_name && !user->user_name) ||
            (!pwent->pw_name && user->user_name) ||
            (pwent->pw_name && user->user_name &&
             strcmp (user->user_name, pwent->pw_name) != 0)) {
                g_free (user->user_name);
                user->user_name = g_strdup (pwent->pw_name);
                g_object_notify (G_OBJECT (user), "user-name");
        }

        /* Home Directory */
        if ((pwent->pw_dir && !user->home_dir) ||
            (!pwent->pw_dir && user->home_dir) ||
            (pwent->pw_dir && user->home_dir &&
             strcmp (user->home_dir, pwent->pw_dir) != 0)) {
                g_free (user->home_dir);
                user->home_dir = g_strdup (pwent->pw_dir);
                g_object_notify (G_OBJECT (user), "home-directory");
        }

        /* Shell */
        if ((pwent->pw_shell && !user->shell) ||
            (!pwent->pw_shell && user->shell) ||
            (pwent->pw_shell && user->shell &&
             strcmp (user->shell, pwent->pw_shell) != 0)) {
                g_free (user->shell);
                user->shell = g_strdup (pwent->pw_shell);
                g_object_notify (G_OBJECT (user), "shell");
        }

        g_object_thaw_notify (G_OBJECT (user));
}

void
user_local_update_from_keyfile (User     *user,
                                GKeyFile *keyfile)
{
        gchar *s;

        g_object_freeze_notify (G_OBJECT (user));

        s = g_key_file_get_string (keyfile, "User", "Language", NULL);
        if (s != NULL) {
                /* TODO: validate / normalize */
                g_free (user->language);
                user->language = s;
        }

        s = g_key_file_get_string (keyfile, "User", "Email", NULL);
        if (s != NULL) {
                g_free (user->email);
                user->email = s;
        }

        s = g_key_file_get_string (keyfile, "User", "Location", NULL);
        if (s != NULL) {
                g_free (user->location);
                user->location = s;
        }

        s = g_key_file_get_string (keyfile, "User", "PasswordHint", NULL);
        if (s != NULL) {
                g_free (user->password_hint);
                user->password_hint = s;
        }

        s = g_key_file_get_string (keyfile, "User", "Icon", NULL);
        g_print ("icon: %s\n", s);
        if (s != NULL) {
                g_free (user->icon_file);
                user->icon_file = s;
        }

        s = g_key_file_get_string (keyfile, "User", "PasswordMode", NULL);
        if (s != NULL) {
                if (strcmp (s, "SetAtLogin") == 0)
                        user->password_mode = PASSWORD_MODE_SET_AT_LOGIN;
                else if (strcmp (s, "None") == 0)
                        user->password_mode = PASSWORD_MODE_NONE;
                else
                        user->password_mode = PASSWORD_MODE_REGULAR;
        }
        else
                user->password_mode = PASSWORD_MODE_REGULAR;

        g_object_thaw_notify (G_OBJECT (user));
}

static void
user_local_save_to_keyfile (User     *user,
                            GKeyFile *keyfile)
{
        if (user->email)
                g_key_file_set_string (keyfile, "User", "Email", user->email);

        if (user->language)
                g_key_file_set_string (keyfile, "User", "Language", user->language);

        if (user->location)
                g_key_file_set_string (keyfile, "User", "Location", user->location);

        if (user->password_hint)
                g_key_file_set_string (keyfile, "User", "PasswordHint", user->password_hint);

        if (user->icon_file)
                g_key_file_set_string (keyfile, "User", "Icon", user->icon_file);

        switch (user->password_mode) {
        case PASSWORD_MODE_SET_AT_LOGIN:
                g_key_file_set_string (keyfile, "User", "PasswordMode", "SetAtLogin");
                break;
        case PASSWORD_MODE_NONE:
                g_key_file_set_string (keyfile, "User", "PasswordMode", "None");
                break;
        default: ;
        }
}

static void
save_extra_data (User *user)
{
        gchar *filename;
        GKeyFile *keyfile;
        gchar *data;
        GError *error;

        keyfile = g_key_file_new ();
        user_local_save_to_keyfile (user, keyfile);

        error = NULL;
        data = g_key_file_to_data (keyfile, NULL, &error);
        if (error == NULL) {
                filename = g_build_filename ("/var/lib/AccountsService/users",
                                             user->user_name,
                                             NULL);
                g_file_set_contents (filename, data, -1, &error);
                g_free (filename);
        }
        if (error) {
                g_warning ("Saving data for user %s failed: %s",
                           user->user_name, error->message);
                g_error_free (error);
        }
        g_key_file_free (keyfile);
}

static void
move_extra_data (const gchar *old_name,
                 const gchar *new_name)
{
        gchar *old_filename;
        gchar *new_filename;

        old_filename = g_build_filename ("/var/lib/AccountsService/users",
                                         old_name,
                                         NULL);
        new_filename = g_build_filename ("/var/lib/AccountsService/users",
                                         new_name,
                                         NULL);

        g_rename (old_filename, new_filename);

        g_free (old_filename);
        g_free (new_filename);
}

static gchar *
compute_object_path (User *user)
{
        gchar *object_path;

        object_path = g_strdup_printf ("/org/freedesktop/Accounts/User%ld", (gint64) user->uid);

        return object_path;
}

void
user_local_register (User *user)
{
        DBusConnection *connection;
        GError *error = NULL;

        user->system_bus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (user->system_bus_connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                goto error;
        }

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        user->object_path = compute_object_path (user);

        if (dbus_g_connection_lookup_g_object (user->system_bus_connection, user->object_path) != NULL) {
                g_critical ("Duplicate object at path %s.", user->object_path);
                goto error;
        }

        dbus_g_connection_register_g_object (user->system_bus_connection,
                                             user->object_path,
                                             G_OBJECT (user));

 error:
        return;
}

void
user_local_unregister (User *user)
{
        dbus_g_connection_unregister_g_object (user->system_bus_connection,
                                               G_OBJECT (user));
}

User *
user_local_new (Daemon *daemon, uid_t uid)
{
        User *user;

        user = g_object_new (TYPE_USER, NULL);
        user->daemon = daemon;
        user->uid = uid;

        return user;
}

const gchar *
user_local_get_user_name (User *user)
{
        return user->user_name;
}

const gchar *
user_local_get_object_path (User *user)
{
        return user->object_path;
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

static void
user_change_real_name_authorized_cb (Daemon *daemon,
                                     User   *user,
                                     DBusGMethodInvocation *context,
                                     gpointer data)

{
        gchar *name = data;
        GError *error;
        gint status;
        gchar *std_out, *std_err;
        gchar *cmdline;

        if (g_strcmp0 (user->real_name, name) != 0) {
                g_warning ("Changing real name of user %s to %s",
                           user->user_name, name);

                cmdline = g_strdup_printf ("/usr/sbin/usermod -c '%s' %s", name, user->user_name);

                std_out = NULL;
                std_err = NULL;
                error = NULL;
                if (!g_spawn_command_line_sync (cmdline, &std_out, &std_err, &status, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", cmdline, error->message);
                        g_error_free (error);
                        g_free (std_out);
                        g_free (std_err);
                        return;
                }

                if (WEXITSTATUS (status) != 0) {
                        throw_error (context, ERROR_FAILED, "usermod returned an error: %s", std_err);
                        g_free (std_out);
                        g_free (std_err);
                        g_free (cmdline);
                        return;
                }

                g_free (std_out);
                g_free (std_err);
                g_free (cmdline);

                g_free (user->real_name);
                user->real_name = g_strdup (name);

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "real-name");
        }

        dbus_g_method_return (context);
}

gboolean
user_set_real_name (User                  *user,
                    const gchar           *real_name,
                    DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_real_name_authorized_cb,
                                 context,
                                 g_strdup (real_name),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_user_name_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     DBusGMethodInvocation *context,
                                     gpointer               data)

{
        gchar *name = data;
        gchar *old_name;
        GError *error;
        gint status;
        gchar *std_out, *std_err;
        gchar *cmdline;

        if (g_strcmp0 (user->user_name, name) != 0) {
                old_name = g_strdup (user->user_name);
                g_warning ("Changing name of user %s to %s", old_name, name);

                cmdline = g_strdup_printf ("/usr/sbin/usermod -l %s %s", name, user->user_name);

                std_out = NULL;
                std_err = NULL;
                error = NULL;
                if (!g_spawn_command_line_sync (cmdline, &std_out, &std_err, &status, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", cmdline, error->message);
                        g_error_free (error);
                        g_free (std_out);
                        g_free (std_err);
                        return;
                }

                if (WEXITSTATUS (status) != 0) {
                        throw_error (context, ERROR_FAILED, "usermod returned an error: %s", std_err);
                        g_free (std_out);
                        g_free (std_err);
                        g_free (cmdline);
                        return;
                }

                g_free (std_out);
                g_free (std_err);
                g_free (cmdline);

                g_free (user->user_name);
                user->user_name = g_strdup (name);

                move_extra_data (old_name, name);

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "user-name");
        }

        dbus_g_method_return (context);
}


gboolean
user_set_user_name (User                  *user,
                    const gchar           *user_name,
                    DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_user_name_authorized_cb,
                                 context,
                                 g_strdup (user_name),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_email_authorized_cb (Daemon *daemon,
                                 User   *user,
                                 DBusGMethodInvocation *context,
                                 gpointer data)

{
        gchar *email = data;

        if (g_strcmp0 (user->email, email) != 0) {
                g_warning ("Changing email of user %s from %s to %s",
                           user->user_name,
                           user->email,
                           email);

                g_free (user->email);
                user->email = g_strdup (email);

                save_extra_data (user);

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "email");
        }

        dbus_g_method_return (context);
}



gboolean
user_set_email (User                  *user,
                const gchar           *email,
                DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_email_authorized_cb,
                                 context,
                                 g_strdup (email),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_language_authorized_cb (Daemon *daemon,
                                    User   *user,
                                    DBusGMethodInvocation *context,
                                    gpointer data)

{
        gchar *language = data;

        if (g_strcmp0 (user->language, language) != 0) {
                g_warning ("Changing language of user %s from %s to %s",
                           user->user_name,
                           user->language,
                           language);

                g_free (user->language);
                user->language = g_strdup (language);

                save_extra_data (user);

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "language");
        }

        dbus_g_method_return (context);
}



gboolean
user_set_language (User                  *user,
                   const gchar           *language,
                   DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_language_authorized_cb,
                                 context,
                                 g_strdup (language),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_location_authorized_cb (Daemon *daemon,
                                    User   *user,
                                    DBusGMethodInvocation *context,
                                    gpointer data)

{
        gchar *location = data;

        if (g_strcmp0 (user->location, location) != 0) {
                g_warning ("Changing location of user %s from %s to %s",
                           user->user_name,
                           user->location,
                           location);

                g_free (user->location);
                user->location = g_strdup (location);

                save_extra_data (user);

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "location");
        }

        dbus_g_method_return (context);
}

gboolean
user_set_location (User                  *user,
                   const gchar           *location,
                   DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_location_authorized_cb,
                                 context,
                                 g_strdup (location),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_home_dir_authorized_cb (Daemon                *daemon,
                                    User                  *user,
                                    DBusGMethodInvocation *context,
                                    gpointer               data)

{
        gchar *home_dir = data;
        GError *error;
        gint status;
        gchar *std_out, *std_err;
        gchar *cmdline;

        if (g_strcmp0 (user->home_dir, home_dir) != 0) {
                g_warning ("Changing home directory of user %s to %s",
                           user->user_name, home_dir);

                cmdline = g_strdup_printf ("/usr/sbin/usermod -m -d '%s' %s", home_dir, user->user_name);

                std_out = NULL;
                std_err = NULL;
                error = NULL;
                if (!g_spawn_command_line_sync (cmdline, &std_out, &std_err, &status, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", cmdline, error->message);
                        g_error_free (error);
                        g_free (std_out);
                        g_free (std_err);
                        return;
                }

                if (WEXITSTATUS (status) != 0) {
                        throw_error (context, ERROR_FAILED, "usermod returned an error: %s", std_err);
                        g_free (std_out);
                        g_free (std_err);
                        g_free (cmdline);
                        return;
                }

                g_free (std_out);
                g_free (std_err);
                g_free (cmdline);

                g_free (user->home_dir);
                user->home_dir = g_strdup (home_dir);

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "home-directory");
        }

        dbus_g_method_return (context);
}
gboolean
user_set_home_directory (User                  *user,
                         const gchar           *home_dir,
                         DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_home_dir_authorized_cb,
                                 context,
                                 g_strdup (home_dir),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_shell_authorized_cb (Daemon                *daemon,
                                 User                  *user,
                                 DBusGMethodInvocation *context,
                                 gpointer               data)

{
        gchar *shell = data;
        GError *error;
        gint status;
        gchar *std_out, *std_err;
        gchar *cmdline;

        if (g_strcmp0 (user->shell, shell) != 0) {
                g_warning ("Changing shell of user %s to %s",
                           user->user_name, shell);

                cmdline = g_strdup_printf ("/usr/sbin/usermod -s '%s' %s", shell, user->user_name);

                std_out = NULL;
                std_err = NULL;
                error = NULL;
                if (!g_spawn_command_line_sync (cmdline, &std_out, &std_err, &status, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", cmdline, error->message);
                        g_error_free (error);
                        g_free (std_out);
                        g_free (std_err);
                        return;
                }

                if (WEXITSTATUS (status) != 0) {
                        throw_error (context, ERROR_FAILED, "usermod returned an error: %s", std_err);
                        g_free (std_out);
                        g_free (std_err);
                        g_free (cmdline);
                        return;
                }

                g_free (std_out);
                g_free (std_err);
                g_free (cmdline);

                g_free (user->shell);
                user->shell = g_strdup (shell);

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "shell");
        }

        dbus_g_method_return (context);
}

gboolean
user_set_shell (User                  *user,
                const gchar           *shell,
                DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_shell_authorized_cb,
                                 context,
                                 g_strdup (shell),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_icon_file_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     DBusGMethodInvocation *context,
                                     gpointer               data)

{
        gchar *filename = data;

        if (g_strcmp0 (user->icon_file, filename) != 0) {
                g_warning ("Changing icon of user %s to %s",
                           user->user_name, filename);

                g_free (user->icon_file);
                user->icon_file = g_strdup (filename);

                save_extra_data (user);

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "icon-file");
        }

        dbus_g_method_return (context);
}

gboolean
user_set_icon_file (User                  *user,
                    const gchar           *filename,
                    DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_icon_file_authorized_cb,
                                 context,
                                 g_strdup (filename),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

typedef struct {
        gint width;
        gint height;
        gint channels;
        gint rowstride;
        guchar *data;
} IconData;

static void
icon_data_free (IconData *data)
{
        g_free (data->data);
        g_free (data);
}

static void
user_change_icon_data_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     DBusGMethodInvocation *context,
                                     gpointer               data)

{
        IconData *id = data;
        GdkPixbuf *pixbuf;
        gchar *filename;
        GError *error;

        g_warning ("Changing icon of user %s", user->user_name);

        pixbuf = gdk_pixbuf_new_from_data (id->data,
                                           GDK_COLORSPACE_RGB,
                                           id->channels == 3 ? FALSE : TRUE,
                                           8,
                                           id->width, id->height,
                                           id->rowstride,
                                           NULL, NULL);
        if (pixbuf == NULL) {
                throw_error (context, ERROR_FAILED, "failed to reconstruct pixbuf");
                return;
        }

        filename = g_build_filename (LOCALSTATE_DIR "/lib/AccountsService/icons",
                                     user->user_name,
                                     NULL);

        error = NULL;
        if (!gdk_pixbuf_save (pixbuf, filename, "png", &error, NULL)) {
                throw_error (context, ERROR_FAILED, "Saving to %s failed: %s", filename, error->message);
                g_object_unref (pixbuf);
                g_free (filename);
                return;
        }

        g_free (user->icon_file);
        user->icon_file = g_strdup (filename);

        save_extra_data (user);

        g_signal_emit (user, signals[CHANGED], 0);

        g_object_notify (G_OBJECT (user), "icon-file");

        dbus_g_method_return (context);
}

gboolean
user_set_icon_data (User                  *user,
                    gint                   width,
                    gint                   height,
                    gint                   channels,
                    gint                   rowstride,
                    GArray                *data,
                    DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;
        IconData *icon_data;

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        icon_data = g_new0 (IconData, 1);
        icon_data->width = width;
        icon_data->height = height;
        icon_data->channels = channels;
        icon_data->rowstride = rowstride;
        /* slightly nasty, we steal the array data here */
        icon_data->data = (guchar *) data->data;
        data->data = NULL;
        data->len = 0;

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_icon_data_authorized_cb,
                                 context,
                                 icon_data,
                                 (GDestroyNotify)icon_data_free);

        return TRUE;
}

static void
user_change_locked_authorized_cb (Daemon                *daemon,
                                  User                  *user,
                                  DBusGMethodInvocation *context,
                                  gpointer               data)

{
        gboolean locked = GPOINTER_TO_INT (data);
        GError *error;
        gint status;
        gchar *std_out, *std_err;
        gchar *cmdline;

        if (user->locked != locked) {
                g_warning ("Changing lockedness of user %s to %d",
                           user->user_name, locked);

                cmdline = g_strdup_printf ("/usr/sbin/usermod -%c %s", locked ? 'L' : 'U',  user->user_name);

                std_out = NULL;
                std_err = NULL;
                error = NULL;
                if (!g_spawn_command_line_sync (cmdline, &std_out, &std_err, &status, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", cmdline, error->message);
                        g_error_free (error);
                        g_free (std_out);
                        g_free (std_err);
                        return;
                }

                if (WEXITSTATUS (status) != 0) {
                        throw_error (context, ERROR_FAILED, "usermod returned an error: %s", std_err);
                        g_free (std_out);
                        g_free (std_err);
                        g_free (cmdline);
                        return;
                }

                g_free (std_out);
                g_free (std_err);
                g_free (cmdline);

                user->locked = locked;

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "locked");
        }

        dbus_g_method_return (context);
}

gboolean
user_set_locked (User                  *user,
                 gboolean               locked,
                 DBusGMethodInvocation *context)
{
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.lock-user",
                                 TRUE,
                                 user_change_locked_authorized_cb,
                                 context,
                                 GINT_TO_POINTER (locked),
                                 NULL);

        return TRUE;
}

static void
user_change_account_type_authorized_cb (Daemon                *daemon,
                                        User                  *user,
                                        DBusGMethodInvocation *context,
                                        gpointer               data)

{
        gint account_type = GPOINTER_TO_INT (data);
        GError *error;
        gint status;
        gchar *std_out, *std_err;
        gchar *cmdline;
        gid_t groups[20];
        gint n_groups;
        GString *str;
        gid_t desktop_user_r;
        gid_t desktop_admin_r;
        struct group *grp;
        gint i;

        if (user->account_type != account_type) {
                g_warning ("Changing account type of user %s to %d",
                           user->user_name, account_type);

                grp = getgrnam ("desktop_user_r");
                if (grp == NULL) {
                        throw_error (context, ERROR_FAILED, "failed to set account type: desktop_user_r group not found");
                        return;
                }
                desktop_user_r = grp->gr_gid;

                grp = getgrnam ("desktop_admin_r");
                if (grp == NULL) {
                        throw_error (context, ERROR_FAILED, "failed to set account type: desktop_admin_r group not found");
                        return;
                }
                desktop_admin_r = grp->gr_gid;

                n_groups = 20;
                if (getgrouplist (user->user_name, user->gid, groups, &n_groups) == -1) {
                        throw_error (context, ERROR_FAILED, "failed to set account type: too many groups");
                        return;
                }

                str = g_string_new ("");
                for (i = 0; i < n_groups; i++) {
                        if (groups[i] == desktop_user_r || groups[i] == desktop_admin_r)
                                continue;
                        g_string_append_printf (str, "%d,", groups[i]);
                }
                switch (account_type) {
                case ACCOUNT_TYPE_STANDARD:
                        g_string_append_printf (str, "%d", desktop_user_r);
                        break;
                case ACCOUNT_TYPE_ADMINISTRATOR:
                        g_string_append_printf (str, "%d", desktop_admin_r);
                        break;
                default:
                        /* remove excess comma */
                        g_string_truncate (str, str->len - 1);
                }

                cmdline = g_strdup_printf ("/usr/sbin/usermod -G %s %s", str->str, user->user_name);

                std_out = NULL;
                std_err = NULL;
                error = NULL;
                if (!g_spawn_command_line_sync (cmdline, &std_out, &std_err, &status, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", cmdline, error->message);
                        g_error_free (error);
                        g_free (std_out);
                        g_free (std_err);
                        return;
                }

                if (WEXITSTATUS (status) != 0) {
                        throw_error (context, ERROR_FAILED, "usermod returned an error: %s", std_err);
                        g_free (std_out);
                        g_free (std_err);
                        g_free (cmdline);
                        return;
                }

                g_free (std_out);
                g_free (std_err);
                g_free (cmdline);

                user->account_type = account_type;

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "account-type");
        }

        dbus_g_method_return (context);
}

gboolean
user_set_account_type (User                  *user,
                       gint                   account_type,
                       DBusGMethodInvocation *context)
{
        if (account_type < 0 || account_type > ACCOUNT_TYPE_LAST) {
                throw_error (context, ERROR_FAILED, "unknown account type: %d", account_type);
                return FALSE;
        }

        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.change-account-type",
                                 TRUE,
                                 user_change_account_type_authorized_cb,
                                 context,
                                 GINT_TO_POINTER (account_type),
                                 NULL);

        return TRUE;
}

static void
user_change_password_mode_authorized_cb (Daemon                *daemon,
                                         User                  *user,
                                         DBusGMethodInvocation *context,
                                         gpointer               data)

{
        gint mode = GPOINTER_TO_INT (data);
        GError *error;
        gint status;
        gchar *std_out, *std_err;
        gchar *cmdline;

        if (user->password_mode != mode) {
                g_warning ("Changing password mode of user %s to %d",
                           user->user_name, mode);

                if (mode == PASSWORD_MODE_SET_AT_LOGIN ||
                    mode == PASSWORD_MODE_NONE) {

                        cmdline = g_strdup_printf ("/usr/bin/passwd -d %s", user->user_name);

                        std_out = NULL;
                        std_err = NULL;
                        error = NULL;
                        if (!g_spawn_command_line_sync (cmdline, &std_out, &std_err, &status, &error)) {
                                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", cmdline, error->message);
                                g_error_free (error);
                                g_free (std_out);
                                g_free (std_err);
                                return;
                        }

                        if (WEXITSTATUS (status) != 0) {
                                throw_error (context, ERROR_FAILED, "usermod returned an error: %s", std_err);
                                g_free (std_out);
                                g_free (std_err);
                                g_free (cmdline);
                                return;
                        }

                        g_free (std_out);
                        g_free (std_err);
                        g_free (cmdline);

                        g_free (user->password_hint);
                        user->password_hint = NULL;

                        g_object_notify (G_OBJECT (user), "password-hint");
                }

                user->password_mode = mode;

                save_extra_data (user);

                g_signal_emit (user, signals[CHANGED], 0);

                g_object_notify (G_OBJECT (user), "password-mode");
        }

        dbus_g_method_return (context);
}

gboolean
user_set_password_mode (User                  *user,
                        gint                   mode,
                        DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;

        if (mode < 0 || mode > PASSWORD_MODE_LAST) {
                throw_error (context, ERROR_FAILED, "unknown password mode: %d", mode);
                return FALSE;
        }

        if (user->locked) {
                throw_error (context, ERROR_FAILED, "account is locked");
                return FALSE;
        }

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_password_mode_authorized_cb,
                                 context,
                                 GINT_TO_POINTER (mode),
                                 NULL);

        return TRUE;
}

static void
user_change_password_authorized_cb (Daemon                *daemon,
                                    User                  *user,
                                    DBusGMethodInvocation *context,
                                    gpointer               data)

{
        gchar **strings = data;
        GError *error;
        gint status;
        gchar *std_out, *std_err;
        gchar *cmdline;

        g_warning ("Changing password of user %s, new hint: %s",
                   user->user_name, strings[1]);

        cmdline = g_strdup_printf ("/usr/sbin/usermod -p '%s' %s", strings[0], user->user_name);

        std_out = NULL;
        std_err = NULL;
        error = NULL;
        if (!g_spawn_command_line_sync (cmdline, &std_out, &std_err, &status, &error)) {
                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", cmdline, error->message);
                g_error_free (error);
                g_free (std_out);
                g_free (std_err);
                return;
        }

        if (WEXITSTATUS (status) != 0) {
                throw_error (context, ERROR_FAILED, "usermod returned an error: %s", std_err);
                g_free (std_out);
                g_free (std_err);
                g_free (cmdline);
                return;
        }

        g_free (std_out);
        g_free (std_err);
        g_free (cmdline);

        if (user->password_mode != PASSWORD_MODE_REGULAR) {
                user->password_mode = PASSWORD_MODE_REGULAR;
                g_object_notify (G_OBJECT (user), "password-mode");
        }

        if (g_strcmp0 (user->password_hint, strings[1]) != 0) {
                g_free (user->password_hint);
                user->password_hint = g_strdup (strings[1]);
                g_object_notify (G_OBJECT (user), "password-hint");
        }

        save_extra_data (user);

        g_signal_emit (user, signals[CHANGED], 0);

        dbus_g_method_return (context);
}

gboolean
user_set_password (User                  *user,
                   const gchar           *password,
                   const gchar           *hint,
                   DBusGMethodInvocation *context)
{
        gchar *sender;
        DBusConnection *connection;
        DBusError dbus_error;
        uid_t uid;
        const gchar *action_id;
        gchar **data;

        if (user->locked) {
                throw_error (context, ERROR_FAILED, "account is locked");
                return FALSE;
        }

        connection = dbus_g_connection_get_connection (user->system_bus_connection);
        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
        if (dbus_error_is_set (&dbus_error)) {
                throw_error (context, ERROR_FAILED, dbus_error.message);
                dbus_error_free (&dbus_error);

                return TRUE;
        }

        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.change-user-data";

        data = g_new (gchar *, 3);
        data[0] = g_strdup (password);
        data[1] = g_strdup (hint);
        data[2] = NULL;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_password_authorized_cb,
                                 context,
                                 data,
                                 (GDestroyNotify)g_strfreev);

        return TRUE;
}
