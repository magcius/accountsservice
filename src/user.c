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

#include "config.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <grp.h>
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif

#include <glib.h>
#include <glib/gi18n.h>
#include <glib-object.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <gio/gunixinputstream.h>
#include <polkit/polkit.h>

#include "daemon.h"
#include "user.h"
#include "accounts-user-generated.h"
#include "util.h"

#define ICONDIR LOCALSTATEDIR "/lib/AccountsService/icons"

enum {
        PROP_0,
        PROP_UID,
        PROP_USER_NAME,
        PROP_REAL_NAME,
        PROP_ACCOUNT_TYPE,
        PROP_HOME_DIR,
        PROP_SHELL,
        PROP_EMAIL,
        PROP_LANGUAGE,
        PROP_X_SESSION,
        PROP_LOCATION,
        PROP_LOGIN_FREQUENCY,
        PROP_ICON_FILE,
        PROP_LOCKED,
        PROP_PASSWORD_MODE,
        PROP_PASSWORD_HINT,
        PROP_AUTOMATIC_LOGIN,
        PROP_SYSTEM_ACCOUNT
};

struct User {
        AccountsUserSkeleton parent;

        GDBusConnection *system_bus_connection;
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
        gchar        *x_session;
        gchar        *location;
        guint64       login_frequency;
        gchar        *icon_file;
        gchar        *default_icon_file;
        gboolean      locked;
        gboolean      automatic_login;
        gboolean      system_account;
};

typedef struct UserClass
{
        AccountsUserSkeletonClass parent_class;
} UserClass;

static void user_accounts_user_iface_init (AccountsUserIface *iface);

G_DEFINE_TYPE_WITH_CODE (User, user, ACCOUNTS_TYPE_USER_SKELETON, G_IMPLEMENT_INTERFACE (ACCOUNTS_TYPE_USER, user_accounts_user_iface_init));

static gint
account_type_from_pwent (struct passwd *pwent)
{
        struct group *grp;
        gid_t wheel;
        gid_t *groups;
        gint ngroups;
        gint i;

        if (pwent->pw_uid == 0) {
                g_debug ("user is root so account type is administrator");
                return ACCOUNT_TYPE_ADMINISTRATOR;
        }

        grp = getgrnam ("wheel");
        if (grp == NULL) {
                g_debug ("wheel group not found");
                return ACCOUNT_TYPE_STANDARD;
        }
        wheel = grp->gr_gid;

        ngroups = get_user_groups (pwent->pw_name, pwent->pw_gid, &groups);

        for (i = 0; i < ngroups; i++) {
                if (groups[i] == wheel) {
                        g_free (groups);
                        return ACCOUNT_TYPE_ADMINISTRATOR;
                }
        }

        g_free (groups);

        return ACCOUNT_TYPE_STANDARD;
}

void
user_local_update_from_pwent (User          *user,
                              struct passwd *pwent)
{
#ifdef HAVE_SHADOW_H
        struct spwd *spent;
#endif
        gchar *real_name;
        gboolean changed;
        const gchar *passwd;
        gboolean locked;
        PasswordMode mode;

        g_object_freeze_notify (G_OBJECT (user));

        changed = FALSE;

        if (pwent->pw_gecos && pwent->pw_gecos[0] != '\0') {
                gchar *first_comma = NULL;
                gchar *valid_utf8_name = NULL;

                if (g_utf8_validate (pwent->pw_gecos, -1, NULL)) {
                        valid_utf8_name = pwent->pw_gecos;
                        first_comma = g_utf8_strchr (valid_utf8_name, -1, ',');
                }
                else {
                        g_warning ("User %s has invalid UTF-8 in GECOS field. "
                                   "It would be a good thing to check /etc/passwd.",
                                   pwent->pw_name ? pwent->pw_name : "");
                }

                if (first_comma) {
                        real_name = g_strndup (valid_utf8_name,
                                                  (first_comma - valid_utf8_name));
                }
                else if (valid_utf8_name) {
                        real_name = g_strdup (valid_utf8_name);
                }
                else {
                        real_name = NULL;
                }

                if (real_name && real_name[0] == '\0') {
                        g_free (real_name);
                        real_name = NULL;
                }
        }
        else {
                real_name = NULL;
        }
        if (g_strcmp0 (real_name, user->real_name) != 0) {
                g_free (user->real_name);
                user->real_name = real_name;
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "real-name");
        }
        else {
                g_free (real_name);
        }

        /* UID */
        if (pwent->pw_uid != user->uid) {
                user->uid = pwent->pw_uid;
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "uid");
        }

        /* GID */
        user->gid = pwent->pw_gid;

        user->account_type = account_type_from_pwent (pwent);

        /* Username */
        if (g_strcmp0 (user->user_name, pwent->pw_name) != 0) {
                g_free (user->user_name);
                user->user_name = g_strdup (pwent->pw_name);
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "user-name");
        }

        /* Home Directory */
        if (g_strcmp0 (user->home_dir, pwent->pw_dir) != 0) {
                g_free (user->home_dir);
                user->home_dir = g_strdup (pwent->pw_dir);
                g_free (user->default_icon_file);
                user->default_icon_file = g_build_filename (user->home_dir, ".face", NULL);
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "home-directory");
        }

        /* Shell */
        if (g_strcmp0 (user->shell, pwent->pw_shell) != 0) {
                g_free (user->shell);
                user->shell = g_strdup (pwent->pw_shell);
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "shell");
        }

        passwd = pwent->pw_passwd;
#ifdef HAVE_SHADOW_H
        spent = getspnam (pwent->pw_name);
        if (spent)
                passwd = spent->sp_pwdp;
#endif

        if (passwd && passwd[0] == '!') {
                locked = TRUE;
        }
        else {
                locked = FALSE;
        }

        if (user->locked != locked) {
                user->locked = locked;
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "locked");
        }

        if (passwd && passwd[0] != 0) {
                mode = PASSWORD_MODE_REGULAR;
        }
        else {
                mode = PASSWORD_MODE_NONE;
        }

#ifdef HAVE_SHADOW_H
        if (spent) {
                if (spent->sp_lstchg == 0) {
                        mode = PASSWORD_MODE_SET_AT_LOGIN;
                }
        }
#endif

        if (user->password_mode != mode) {
                user->password_mode = mode;
                changed = TRUE;
                g_object_notify (G_OBJECT (user), "password-mode");
        }

        user->system_account = daemon_local_user_is_excluded (user->daemon,
                                                              user->user_name,
                                                              pwent->pw_shell);

        g_object_thaw_notify (G_OBJECT (user));

        if (changed)
                accounts_user_emit_changed (ACCOUNTS_USER (user));
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

        s = g_key_file_get_string (keyfile, "User", "XSession", NULL);
        if (s != NULL) {
                g_free (user->x_session);
                user->x_session = s;
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
        if (s != NULL) {
                g_free (user->icon_file);
                user->icon_file = s;
        }

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

        if (user->x_session)
                g_key_file_set_string (keyfile, "User", "XSession", user->x_session);

        if (user->location)
                g_key_file_set_string (keyfile, "User", "Location", user->location);

        if (user->password_hint)
                g_key_file_set_string (keyfile, "User", "PasswordHint", user->password_hint);

        if (user->icon_file)
                g_key_file_set_string (keyfile, "User", "Icon", user->icon_file);
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
                                         old_name, NULL);
        new_filename = g_build_filename ("/var/lib/AccountsService/users",
                                         new_name, NULL);

        g_rename (old_filename, new_filename);

        g_free (old_filename);
        g_free (new_filename);
}

static gchar *
compute_object_path (User *user)
{
        gchar *object_path;

        object_path = g_strdup_printf ("/org/freedesktop/Accounts/User%ld",
                                       (long) user->uid);

        return object_path;
}

void
user_local_register (User *user)
{
        GError *error = NULL;

        user->system_bus_connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
        if (user->system_bus_connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                return;
        }

        user->object_path = compute_object_path (user);

        if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (user),
                                               user->system_bus_connection,
                                               user->object_path,
                                               &error)) {
                if (error != NULL) {
                        g_critical ("error exporting user object: %s", error->message);
                        g_error_free (error);
                }
                return;
        }
}

void
user_local_unregister (User *user)
{
        g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (user));
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

uid_t
user_local_get_uid (User *user)
{
        return user->uid;
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

static void
user_change_real_name_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     GDBusMethodInvocation *context,
                                     gpointer               data)

{
        gchar *name = data;
        GError *error;
        const gchar *argv[6];

        if (g_strcmp0 (user->real_name, name) != 0) {
                sys_log (context,
                         "change real name of user '%s' (%d) to '%s'",
                         user->user_name, user->uid, name);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-c";
                argv[2] = name;
                argv[3] = "--";
                argv[4] = user->user_name;
                argv[5] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                g_free (user->real_name);
                user->real_name = g_strdup (name);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "real-name");
        }

        accounts_user_complete_set_real_name (ACCOUNTS_USER (user), context);
}

static uid_t
method_invocation_get_uid (GDBusMethodInvocation *context)
{
  const gchar *sender;
  PolkitSubject *busname;
  PolkitSubject *process;
  uid_t uid;

  sender = g_dbus_method_invocation_get_sender (context);
  busname = polkit_system_bus_name_new (sender);
  process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (busname), NULL, NULL);
  uid = polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (process));
  g_object_unref (busname);
  g_object_unref (process);

  return uid;
}

static gboolean
user_set_real_name (AccountsUser          *auser,
                    GDBusMethodInvocation *context,
                    const gchar           *real_name)
{
        User *user = (User*)auser;
        uid_t uid;
        const gchar *action_id;

        uid = method_invocation_get_uid (context);
        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

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
                                     GDBusMethodInvocation *context,
                                     gpointer               data)

{
        gchar *name = data;
        gchar *old_name;
        GError *error;
        const gchar *argv[6];

        if (g_strcmp0 (user->user_name, name) != 0) {
                old_name = g_strdup (user->user_name);
                sys_log (context,
                         "change name of user '%s' (%d) to '%s'",
                         old_name, user->uid, name);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-l";
                argv[2] = name;
                argv[3] = "--";
                argv[4] = user->user_name;
                argv[5] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                g_free (user->user_name);
                user->user_name = g_strdup (name);

                move_extra_data (old_name, name);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "user-name");
        }

        accounts_user_complete_set_user_name (ACCOUNTS_USER (user), context);
}


static gboolean
user_set_user_name (AccountsUser          *auser,
                    GDBusMethodInvocation *context,
                    const gchar           *user_name)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_user_name_authorized_cb,
                                 context,
                                 g_strdup (user_name),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
user_change_email_authorized_cb (Daemon                *daemon,
                                 User                  *user,
                                 GDBusMethodInvocation *context,
                                 gpointer               data)

{
        gchar *email = data;

        if (g_strcmp0 (user->email, email) != 0) {
                g_free (user->email);
                user->email = g_strdup (email);

                save_extra_data (user);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "email");
        }

        accounts_user_complete_set_email (ACCOUNTS_USER (user), context);  
}



static gboolean
user_set_email (AccountsUser          *auser,
                GDBusMethodInvocation *context,
                const gchar           *email)
{
        User *user = (User*)auser;
        uid_t uid;
        const gchar *action_id;

        uid = method_invocation_get_uid (context);
        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

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
user_change_language_authorized_cb (Daemon                *daemon,
                                    User                  *user,
                                    GDBusMethodInvocation *context,
                                    gpointer               data)

{
        gchar *language = data;

        if (g_strcmp0 (user->language, language) != 0) {
                g_free (user->language);
                user->language = g_strdup (language);

                save_extra_data (user);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "language");
        }

        accounts_user_complete_set_language (ACCOUNTS_USER (user), context);
}



static gboolean
user_set_language (AccountsUser          *auser,
                   GDBusMethodInvocation *context,
                   const gchar           *language)
{
        User *user = (User*)auser;
        uid_t uid;
        const gchar *action_id;

        uid = method_invocation_get_uid (context);
        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

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
user_change_x_session_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     GDBusMethodInvocation *context,
                                     gpointer               data)

{
        gchar *x_session = data;

        if (g_strcmp0 (user->x_session, x_session) != 0) {
                g_free (user->x_session);
                user->x_session = g_strdup (x_session);

                save_extra_data (user);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "xsession");
        }

        accounts_user_complete_set_xsession (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_x_session (AccountsUser          *auser,
                    GDBusMethodInvocation *context,
                    const gchar           *x_session)
{
        User *user = (User*)auser;
        uid_t uid;
        const gchar *action_id;

        uid = method_invocation_get_uid (context);
        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

        daemon_local_check_auth (user->daemon,
                                 user,
                                 action_id,
                                 TRUE,
                                 user_change_x_session_authorized_cb,
                                 context,
                                 g_strdup (x_session),
                                 (GDestroyNotify) g_free);

        return TRUE;
}

static void
user_change_location_authorized_cb (Daemon                *daemon,
                                    User                  *user,
                                    GDBusMethodInvocation *context,
                                    gpointer               data)

{
        gchar *location = data;

        if (g_strcmp0 (user->location, location) != 0) {
                g_free (user->location);
                user->location = g_strdup (location);

                save_extra_data (user);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "location");
        }

        accounts_user_complete_set_location (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_location (AccountsUser          *auser,
                   GDBusMethodInvocation *context,
                   const gchar           *location)
{
        User *user = (User*)auser;
        uid_t uid;
        const gchar *action_id;

        uid = method_invocation_get_uid (context);
        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

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
                                    GDBusMethodInvocation *context,
                                    gpointer               data)

{
        gchar *home_dir = data;
        GError *error;
        const gchar *argv[7];

        if (g_strcmp0 (user->home_dir, home_dir) != 0) {
                sys_log (context,
                         "change home directory of user '%s' (%d) to '%s'",
                         user->user_name, user->uid, home_dir);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-m";
                argv[2] = "-d";
                argv[3] = home_dir;
                argv[4] = "--";
                argv[5] = user->user_name;
                argv[6] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                g_free (user->home_dir);
                user->home_dir = g_strdup (home_dir);
                g_free (user->default_icon_file);
                user->default_icon_file = g_build_filename (user->home_dir, ".face", NULL);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "home-directory");
        }

        accounts_user_complete_set_home_directory (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_home_directory (AccountsUser          *auser,
                         GDBusMethodInvocation *context,
                         const gchar           *home_dir)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
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
                                 GDBusMethodInvocation *context,
                                 gpointer               data)

{
        gchar *shell = data;
        GError *error;
        const gchar *argv[6];

        if (g_strcmp0 (user->shell, shell) != 0) {
                sys_log (context,
                         "change shell of user '%s' (%d) to '%s'",
                         user->user_name, user->uid, shell);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-s";
                argv[2] = shell;
                argv[3] = "--";
                argv[4] = user->user_name;
                argv[5] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                g_free (user->shell);
                user->shell = g_strdup (shell);

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "shell");
        }

        accounts_user_complete_set_shell (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_shell (AccountsUser          *auser,
                GDBusMethodInvocation *context,
                const gchar           *shell)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_shell_authorized_cb,
                                 context,
                                 g_strdup (shell),
                                 (GDestroyNotify)g_free);

        return TRUE;
}

static void
become_user (gpointer data)
{
        struct passwd *pw = data;

        if (pw == NULL ||
            initgroups (pw->pw_name, pw->pw_gid) != 0 ||
            setgid (pw->pw_gid) != 0 ||
            setuid (pw->pw_uid) != 0) {
                exit (1);
        }
}

static void
user_change_icon_file_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     GDBusMethodInvocation *context,
                                     gpointer               data)

{
        gchar *filename;
        GFile *file;
        GFileInfo *info;
        guint32 mode;
        GFileType type;
        guint64 size;

        filename = g_strdup (data);

        if (filename == NULL ||
            *filename == '\0') {
                char *dest_path;
                GFile *dest;
                GError *error;

                g_free (filename);
                filename = NULL;

                dest_path = g_build_filename (ICONDIR, user->user_name, NULL);
                dest = g_file_new_for_path (dest_path);
                g_free (dest_path);

                error = NULL;
                if (!g_file_delete (dest, NULL, &error) &&
                    !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND)) {
                        g_object_unref (dest);
                        throw_error (context, ERROR_FAILED, "failed to remove user icon, %s", error->message);
                        g_error_free (error);
                        return;
                }
                g_object_unref (dest);
                goto icon_saved;
        }

        file = g_file_new_for_path (filename);
        info = g_file_query_info (file, G_FILE_ATTRIBUTE_UNIX_MODE ","
                                        G_FILE_ATTRIBUTE_STANDARD_TYPE ","
                                        G_FILE_ATTRIBUTE_STANDARD_SIZE,
                                  0, NULL, NULL);
        mode = g_file_info_get_attribute_uint32 (info, G_FILE_ATTRIBUTE_UNIX_MODE);
        type = g_file_info_get_file_type (info);
        size = g_file_info_get_attribute_uint64 (info, G_FILE_ATTRIBUTE_STANDARD_SIZE);

        g_object_unref (info);
        g_object_unref (file);

        if (type != G_FILE_TYPE_REGULAR) {
                g_debug ("not a regular file\n");
                throw_error (context, ERROR_FAILED, "file '%s' is not a regular file", filename);
                g_free (filename);
                return;
        }

        if (size > 1048576) {
                g_debug ("file too large\n");
                /* 1MB ought to be enough for everybody */
                throw_error (context, ERROR_FAILED, "file '%s' is too large to be used as an icon", filename);
                g_free (filename);
                return;
        }

        if ((mode & S_IROTH) == 0 ||
            (!g_str_has_prefix (filename, DATADIR) &&
             !g_str_has_prefix (filename, ICONDIR))) {
                gchar *dest_path;
                GFile *dest;
                const gchar *argv[3];
                gint std_out;
                GError *error;
                GInputStream *input;
                GOutputStream *output;
                gint uid;
                gssize bytes;
                struct passwd *pw;

                if (!get_caller_uid (context, &uid)) {
                        throw_error (context, ERROR_FAILED, "failed to copy file, could not determine caller UID");
                        g_free (filename);
                        return;
                }

                dest_path = g_build_filename (ICONDIR, user->user_name, NULL);
                dest = g_file_new_for_path (dest_path);

                error = NULL;
                output = G_OUTPUT_STREAM (g_file_replace (dest, NULL, FALSE, 0, NULL, &error));
                if (!output) {
                        throw_error (context, ERROR_FAILED, "creating file '%s' failed: %s", dest_path, error->message);
                        g_error_free (error);
                        g_free (filename);
                        g_free (dest_path);
                        g_object_unref (dest);
                        return;
                }

                argv[0] = "/bin/cat";
                argv[1] = filename;
                argv[2] = NULL;

                pw = getpwuid (uid);

                error = NULL;
                if (!g_spawn_async_with_pipes (NULL, (gchar**)argv, NULL, 0, become_user, pw, NULL, NULL, &std_out, NULL, &error)) {
                        throw_error (context, ERROR_FAILED, "reading file '%s' failed: %s", filename, error->message);
                        g_error_free (error);
                        g_free (filename);
                        g_free (dest_path);
                        g_object_unref (dest);
                        return;
                }

                input = g_unix_input_stream_new (std_out, FALSE);

                error = NULL;
                bytes = g_output_stream_splice (output, input, G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET, NULL, &error);
                if (bytes < 0 || (gsize)bytes != size) {
                        throw_error (context, ERROR_FAILED, "copying file '%s' to '%s' failed: %s", filename, dest_path, error ? error->message : "unknown reason");
                        if (error)
                                g_error_free (error);

                        g_file_delete (dest, NULL, NULL);

                        g_free (filename);
                        g_free (dest_path);
                        g_object_unref (dest);
                        g_object_unref (input);
                        g_object_unref (output);
                        return;
                }

                g_object_unref (dest);
                g_object_unref (input);
                g_object_unref (output);

                g_free (filename);
                filename = dest_path;
        }

icon_saved:
        g_free (user->icon_file);
        user->icon_file = filename;

        save_extra_data (user);

        accounts_user_emit_changed (ACCOUNTS_USER (user));

        g_object_notify (G_OBJECT (user), "icon-file");

        accounts_user_complete_set_icon_file (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_icon_file (AccountsUser          *auser,
                    GDBusMethodInvocation *context,
                    const gchar           *filename)
{
        User *user = (User*)auser;
        uid_t uid;
        const gchar *action_id;

        uid = method_invocation_get_uid (context);
        if (user->uid == uid)
                action_id = "org.freedesktop.accounts.change-own-user-data";
        else
                action_id = "org.freedesktop.accounts.user-administration";

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

static void
user_change_locked_authorized_cb (Daemon                *daemon,
                                  User                  *user,
                                  GDBusMethodInvocation *context,
                                  gpointer               data)

{
        gboolean locked = GPOINTER_TO_INT (data);
        GError *error;
        const gchar *argv[5];

        if (user->locked != locked) {
                sys_log (context,
                         "%s account of user '%s' (%d)",
                         locked ? "locking" : "unlocking", user->user_name, user->uid);
                argv[0] = "/usr/sbin/usermod";
                argv[1] = locked ? "-L" : "-U";
                argv[2] = "--";
                argv[3] = user->user_name;
                argv[4] = NULL;

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                user->locked = locked;

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "locked");
        }

        accounts_user_complete_set_locked (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_locked (AccountsUser          *auser,
                 GDBusMethodInvocation *context,
                 gboolean               locked)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
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
                                        GDBusMethodInvocation *context,
                                        gpointer               data)

{
        AccountType account_type = GPOINTER_TO_INT (data);
        GError *error;
        gid_t *groups;
        gint ngroups;
        GString *str;
        gid_t wheel;
        struct group *grp;
        gint i;
        const gchar *argv[6];

        if (user->account_type != account_type) {
                sys_log (context,
                         "change account type of user '%s' (%d) to %d",
                         user->user_name, user->uid, account_type);

                grp = getgrnam ("wheel");
                if (grp == NULL) {
                        throw_error (context, ERROR_FAILED, "failed to set account type: wheel group not found");
                        return;
                }
                wheel = grp->gr_gid;

                ngroups = get_user_groups (user->user_name, user->gid, &groups);

                str = g_string_new ("");
                for (i = 0; i < ngroups; i++) {
                        if (groups[i] == wheel)
                                continue;
                        g_string_append_printf (str, "%d,", groups[i]);
                }
                switch (account_type) {
                case ACCOUNT_TYPE_ADMINISTRATOR:
                        g_string_append_printf (str, "%d", wheel);
                        break;
                case ACCOUNT_TYPE_STANDARD:
                default:
                        /* remove excess comma */
                        g_string_truncate (str, str->len - 1);
                        break;
                }

                g_free (groups);

                argv[0] = "/usr/sbin/usermod";
                argv[1] = "-G";
                argv[2] = str->str;
                argv[3] = "--";
                argv[4] = user->user_name;
                argv[5] = NULL;

                g_string_free (str, FALSE);

                error = NULL;
                if (!spawn_with_login_uid (context, argv, &error)) {
                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                        g_error_free (error);
                        return;
                }

                user->account_type = account_type;

                accounts_user_emit_changed (ACCOUNTS_USER (user));

                g_object_notify (G_OBJECT (user), "account-type");
        }

        accounts_user_complete_set_account_type (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_account_type (AccountsUser          *auser,
                       GDBusMethodInvocation *context,
                       gint                   account_type)
{
        User *user = (User*)auser;
        if (account_type < 0 || account_type > ACCOUNT_TYPE_LAST) {
                throw_error (context, ERROR_FAILED, "unknown account type: %d", account_type);
                return FALSE;
        }

        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
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
                                         GDBusMethodInvocation *context,
                                         gpointer               data)

{
        PasswordMode mode = GPOINTER_TO_INT (data);
        GError *error;
        const gchar *argv[6];

        if (user->password_mode != mode) {
                sys_log (context,
                         "change password mode of user '%s' (%d) to %d",
                         user->user_name, user->uid, mode);

                g_object_freeze_notify (G_OBJECT (user));

                if (mode == PASSWORD_MODE_SET_AT_LOGIN ||
                    mode == PASSWORD_MODE_NONE) {

                        argv[0] = "/usr/bin/passwd";
                        argv[1] = "-d";
                        argv[2] = "--";
                        argv[3] = user->user_name;
                        argv[4] = NULL;

                        error = NULL;
                        if (!spawn_with_login_uid (context, argv, &error)) {
                                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                                g_error_free (error);
                                return;
                        }

                        if (mode == PASSWORD_MODE_SET_AT_LOGIN) {
                                argv[0] = "/usr/bin/chage";
                                argv[1] = "-d";
                                argv[2] = "0";
                                argv[3] = "--";
                                argv[4] = user->user_name;
                                argv[5] = NULL;

                                error = NULL;
                                if (!spawn_with_login_uid (context, argv, &error)) {
                                        throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                                        g_error_free (error);
                                        return;
                                }
                        }

                        g_free (user->password_hint);
                        user->password_hint = NULL;

                        g_object_notify (G_OBJECT (user), "password-hint");

                        /* removing the password has the side-effect of
                         * unlocking the account
                         */
                        if (user->locked) {
                                user->locked = FALSE;
                                g_object_notify (G_OBJECT (user), "locked");
                        }
                }
                else if (user->locked) {
                        argv[0] = "/usr/sbin/usermod";
                        argv[1] = "-U";
                        argv[2] = "--";
                        argv[3] = user->user_name;
                        argv[4] = NULL;

                        error = NULL;
                        if (!spawn_with_login_uid (context, argv, &error)) {
                                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                                g_error_free (error);
                                return;
                        }

                        user->locked = FALSE;
                        g_object_notify (G_OBJECT (user), "locked");
                }

                user->password_mode = mode;

                g_object_notify (G_OBJECT (user), "password-mode");

                save_extra_data (user);

                g_object_thaw_notify (G_OBJECT (user));

                accounts_user_emit_changed (ACCOUNTS_USER (user));
        }

        accounts_user_complete_set_password_mode (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_password_mode (AccountsUser          *auser,
                        GDBusMethodInvocation *context,
                        gint                   mode)
{
        User *user = (User*)auser;
        const gchar *action_id;

        if (mode < 0 || mode > PASSWORD_MODE_LAST) {
                throw_error (context, ERROR_FAILED, "unknown password mode: %d", mode);
                return FALSE;
        }

        action_id = "org.freedesktop.accounts.user-administration";

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
                                    GDBusMethodInvocation *context,
                                    gpointer               data)

{
        gchar **strings = data;
        GError *error;
        const gchar *argv[6];

        sys_log (context,
                 "set password and hint of user '%s' (%d)",
                 user->user_name, user->uid);

        g_object_freeze_notify (G_OBJECT (user));

        argv[0] = "/usr/sbin/usermod";
        argv[1] = "-p";
        argv[2] = strings[0];
        argv[3] = "--";
        argv[4] = user->user_name;
        argv[5] = NULL;

        error = NULL;
        if (!spawn_with_login_uid (context, argv, &error)) {
                throw_error (context, ERROR_FAILED, "running '%s' failed: %s", argv[0], error->message);
                g_error_free (error);
                return;
        }

        if (user->password_mode != PASSWORD_MODE_REGULAR) {
                user->password_mode = PASSWORD_MODE_REGULAR;
                g_object_notify (G_OBJECT (user), "password-mode");
        }

        if (user->locked) {
                user->locked = FALSE;
                g_object_notify (G_OBJECT (user), "locked");
        }

        if (g_strcmp0 (user->password_hint, strings[1]) != 0) {
                g_free (user->password_hint);
                user->password_hint = g_strdup (strings[1]);
                g_object_notify (G_OBJECT (user), "password-hint");
        }

        save_extra_data (user);

        g_object_thaw_notify (G_OBJECT (user));

        accounts_user_emit_changed (ACCOUNTS_USER (user));

        accounts_user_complete_set_password (ACCOUNTS_USER (user), context);
}

static void
free_passwords (gchar **strings)
{
        memset (strings[0], 0, strlen (strings[0]));
        g_strfreev (strings);
}

static gboolean
user_set_password (AccountsUser          *auser,
                   GDBusMethodInvocation *context,
                   const gchar           *password,
                   const gchar           *hint)
{
        User *user = (User*)auser;
        gchar **data;

        data = g_new (gchar *, 3);
        data[0] = g_strdup (password);
        data[1] = g_strdup (hint);
        data[2] = NULL;

        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_password_authorized_cb,
                                 context,
                                 data,
                                 (GDestroyNotify)free_passwords);

        memset ((char*)password, 0, strlen (password));

        return TRUE;
}

static void
user_change_automatic_login_authorized_cb (Daemon                *daemon,
                                           User                  *user,
                                           GDBusMethodInvocation *context,
                                           gpointer               data)
{
        gboolean enabled = GPOINTER_TO_INT (data);
        GError *error = NULL;

        sys_log (context,
                 "%s automatic login for user '%s' (%d)",
                 enabled ? "enable" : "disable", user->user_name, user->uid);

        if (!daemon_local_set_automatic_login (daemon, user, enabled, &error)) {
                throw_error (context, ERROR_FAILED, "failed to change automatic login: %s", error->message);
                g_error_free (error);
                return;
        }

        accounts_user_complete_set_automatic_login (ACCOUNTS_USER (user), context);
}

static gboolean
user_set_automatic_login (AccountsUser          *auser,
                          GDBusMethodInvocation *context,
                          gboolean               enabled)
{
        User *user = (User*)auser;
        daemon_local_check_auth (user->daemon,
                                 user,
                                 "org.freedesktop.accounts.user-administration",
                                 TRUE,
                                 user_change_automatic_login_authorized_cb,
                                 context,
                                 GINT_TO_POINTER (enabled),
                                 NULL);

        return TRUE;
}

static guint64
user_get_uid (AccountsUser *user)
{
        return (guint64) USER (user)->uid;
}

static const gchar *
user_get_user_name (AccountsUser *user)
{
        return USER (user)->user_name;
}

static const gchar *
user_get_real_name (AccountsUser *user)
{
        return USER (user)->real_name;
}

static gint
user_get_account_type (AccountsUser *user)
{
        return (gint) USER (user)->account_type;
}

static const gchar *
user_get_home_directory (AccountsUser *user)
{
        return USER (user)->home_dir;
}

static const gchar *
user_get_shell (AccountsUser *user)
{
        return USER (user)->shell;
}

static const gchar *
user_get_email (AccountsUser *user)
{
        return USER (user)->email;
}

static const gchar *
user_get_language (AccountsUser *user)
{
        return USER (user)->language;
}

static const gchar *
user_get_xsession (AccountsUser *user)
{
        return USER (user)->x_session;
}

static const gchar *
user_get_location (AccountsUser *user)
{
        return USER (user)->location;
}

static guint64
user_get_login_frequency (AccountsUser *user)
{
        return USER (user)->login_frequency;
}

static const gchar *
user_get_icon_file (AccountsUser *user)
{
        if (USER (user)->icon_file)
                return USER (user)->icon_file;
        else
                return USER (user)->default_icon_file;
}

static gboolean
user_get_locked (AccountsUser *user)
{
        return USER (user)->locked;
}

static gint
user_get_password_mode (AccountsUser *user)
{
        return USER (user)->password_mode;
}

static const gchar *
user_get_password_hint (AccountsUser *user)
{
        return USER (user)->password_hint;
}

static gboolean
user_get_automatic_login (AccountsUser *user)
{
        return USER (user)->automatic_login;
}

static gboolean
user_get_system_account (AccountsUser *user)
{
        return USER (user)->system_account;
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
        g_free (user->default_icon_file);
        g_free (user->email);
        g_free (user->language);
        g_free (user->x_session);
        g_free (user->location);
        g_free (user->password_hint);

        if (G_OBJECT_CLASS (user_parent_class)->finalize)
                (*G_OBJECT_CLASS (user_parent_class)->finalize) (object);
}

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
        case PROP_X_SESSION:
                user->x_session = g_value_dup_string (value);
                break;
        case PROP_EMAIL:
                user->email = g_value_dup_string (value);
                break;
        case PROP_LOGIN_FREQUENCY:
                user->login_frequency = g_value_get_uint64 (value);
                break;
        case PROP_AUTOMATIC_LOGIN:
                user->automatic_login = g_value_get_boolean (value);
                break;
        case PROP_SYSTEM_ACCOUNT:
                user->system_account = g_value_get_boolean (value);
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
        case PROP_X_SESSION:
                g_value_set_string (value, user->x_session);
                break;
        case PROP_LOCATION:
                g_value_set_string (value, user->location);
                break;
        case PROP_ICON_FILE:
                if (user->icon_file)
                        g_value_set_string (value, user->icon_file);
                else {
                        gchar *icon_file;

                        icon_file = g_build_filename (user->home_dir, ".face", NULL);
                        g_value_take_string (value, icon_file);
                }
                break;
        case PROP_LOGIN_FREQUENCY:
                g_value_set_uint64 (value, user->login_frequency);
                break;
        case PROP_LOCKED:
                g_value_set_boolean (value, user->locked);
                break;
        case PROP_AUTOMATIC_LOGIN:
                g_value_set_boolean (value, user->automatic_login);
                break;
        case PROP_SYSTEM_ACCOUNT:
                g_value_set_boolean (value, user->system_account);
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

        accounts_user_override_properties (gobject_class, 1);
}

static void
user_accounts_user_iface_init (AccountsUserIface *iface)
{
        iface->handle_set_account_type = user_set_account_type;
        iface->handle_set_automatic_login = user_set_automatic_login;
        iface->handle_set_email = user_set_email;
        iface->handle_set_home_directory = user_set_home_directory;
        iface->handle_set_icon_file = user_set_icon_file;
        iface->handle_set_language = user_set_language;
        iface->handle_set_location = user_set_location;
        iface->handle_set_locked = user_set_locked;
        iface->handle_set_password = user_set_password;
        iface->handle_set_password_mode = user_set_password_mode;
        iface->handle_set_real_name = user_set_real_name;
        iface->handle_set_shell = user_set_shell;
        iface->handle_set_user_name = user_set_user_name;
        iface->handle_set_xsession = user_set_x_session;
        iface->get_uid = user_get_uid;
        iface->get_user_name = user_get_user_name;
        iface->get_real_name = user_get_real_name;
        iface->get_account_type = user_get_account_type;
        iface->get_home_directory = user_get_home_directory;
        iface->get_shell = user_get_shell;
        iface->get_email = user_get_email;
        iface->get_language = user_get_language;
        iface->get_xsession = user_get_xsession;
        iface->get_location = user_get_location;
        iface->get_login_frequency = user_get_login_frequency;
        iface->get_icon_file = user_get_icon_file;
        iface->get_locked = user_get_locked;
        iface->get_password_mode = user_get_password_mode;
        iface->get_password_hint = user_get_password_hint;
        iface->get_automatic_login = user_get_automatic_login;
        iface->get_system_account = user_get_system_account;
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
        user->default_icon_file = NULL;
        user->email = NULL;
        user->language = NULL;
        user->x_session = NULL;
        user->location = NULL;
        user->password_mode = PASSWORD_MODE_REGULAR;
        user->password_hint = NULL;
        user->locked = FALSE;
        user->automatic_login = FALSE;
        user->system_account = FALSE;
}
