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
        PROP_ACCOUNT_TYPE,
        PROP_PASSWORD_MODE,
        PROP_PASSWORD_HINT,
        PROP_HOME_DIR,
        PROP_SHELL,
        PROP_EMAIL,
        PROP_LOCATION,
        PROP_LOCKED,
        PROP_AUTOMATIC_LOGIN,
        PROP_LOGIN_FREQUENCY,
        PROP_ICON_FILE,
        PROP_LANGUAGE,
        PROP_X_SESSION,
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
        char           *password_hint;
        char           *home_dir;
        char           *shell;
        char           *email;
        char           *location;
        char           *icon_file;
        char           *language;
        char           *x_session;
        GList          *sessions;
        int             login_frequency;

        ActUserAccountType  account_type;
        ActUserPasswordMode password_mode;

        guint           is_loaded : 1;
        guint           locked : 1;
        guint           automatic_login : 1;
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
        case PROP_LOGIN_FREQUENCY:
                g_value_set_int (value, user->login_frequency);
                break;
        case PROP_SHELL:
                g_value_set_string (value, user->shell);
                break;
        case PROP_EMAIL:
                g_value_set_string (value, user->email);
                break;
        case PROP_LOCATION:
                g_value_set_string (value, user->location);
                break;
        case PROP_ICON_FILE:
                g_value_set_string (value, user->icon_file);
                break;
        case PROP_LANGUAGE:
                g_value_set_string (value, user->language);
                break;
        case PROP_X_SESSION:
                g_value_set_string (value, user->x_session);
                break;
        case PROP_LOCKED:
                g_value_set_boolean (value, user->locked);
                break;
        case PROP_AUTOMATIC_LOGIN:
                g_value_set_boolean (value, user->automatic_login);
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
                                         PROP_ACCOUNT_TYPE,
                                         g_param_spec_int ("account-type",
                                                           "Account Type",
                                                           "The account type for this user.",
                                                           ACT_USER_ACCOUNT_TYPE_STANDARD,
                                                           ACT_USER_ACCOUNT_TYPE_ADMINISTRATOR,
                                                           ACT_USER_ACCOUNT_TYPE_STANDARD,
                                                           G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_PASSWORD_MODE,
                                         g_param_spec_int ("password-mode",
                                                           "Password Mode",
                                                           "The password mode for this user.",
                                                           ACT_USER_PASSWORD_MODE_REGULAR,
                                                           ACT_USER_PASSWORD_MODE_NONE,
                                                           ACT_USER_PASSWORD_MODE_REGULAR,
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
                                         PROP_LOCATION,
                                         g_param_spec_string ("location",
                                                              "Location",
                                                              "The location of this user.",
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
                                         PROP_X_SESSION,
                                         g_param_spec_string ("x-session",
                                                              "X session",
                                                              "User's X session.",
                                                              NULL,
                                                              G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_IS_LOADED,
                                         g_param_spec_boolean ("is-loaded",
                                                               NULL,
                                                               NULL,
                                                               FALSE,
                                                               G_PARAM_READABLE));
        g_object_class_install_property (gobject_class,
                                         PROP_LOCKED,
                                         g_param_spec_boolean ("locked",
                                                               "Locked",
                                                               "Locked",
                                                               FALSE,
                                                              G_PARAM_READABLE));

        g_object_class_install_property (gobject_class,
                                         PROP_AUTOMATIC_LOGIN,
                                         g_param_spec_boolean ("automatic-login",
                                                               "Automatic Login",
                                                               "Automatic Login",
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
        g_free (user->password_hint);
        g_free (user->home_dir);
        g_free (user->shell);
        g_free (user->email);
        g_free (user->location);
        g_free (user->language);

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

        if (user->real_name == NULL ||
            user->real_name[0] == '\0') {
                return user->user_name;
        }

        return user->real_name;
}

/**
 * act_user_get_account_type:
 * @user: the user object to examine.
 *
 * Retrieves the account type of @user.
 *
 * Returns: a #ActUserAccountType
 **/
ActUserAccountType
act_user_get_account_type (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), ACT_USER_ACCOUNT_TYPE_STANDARD);

        return user->account_type;
}

/**
 * act_user_get_password_mode:
 * @user: the user object to examine.
 *
 * Retrieves the password mode of @user.
 *
 * Returns: a #ActUserPasswordMode
 **/
ActUserPasswordMode
act_user_get_password_mode (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), ACT_USER_PASSWORD_MODE_REGULAR);

        return user->password_mode;
}

/**
 * act_user_get_password_hint:
 * @user: the user object to examine.
 *
 * Retrieves the password hint set by @user.
 *
 * Returns: (transfer none): a pointer to an array of characters which must not be modified or
 *  freed, or %NULL.
 **/
const char *
act_user_get_password_hint (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->password_hint;
}

/**
 * act_user_get_home_dir:
 * @user: the user object to examine.
 *
 * Retrieves the home directory for @user.
 *
 * Returns: (transfer none): a pointer to an array of characters which must not be modified or
 *  freed, or %NULL.
 **/
const char *
act_user_get_home_dir (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->home_dir;
}

/**
 * act_user_get_shell:
 * @user: the user object to examine.
 *
 * Retrieves the shell assigned to @user.
 *
 * Returns: (transfer none): a pointer to an array of characters which must not be modified or
 *  freed, or %NULL.
 **/
const char *
act_user_get_shell (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->shell;
}

/**
 * act_user_get_email:
 * @user: the user object to examine.
 *
 * Retrieves the email address set by @user.
 *
 * Returns: (transfer none): a pointer to an array of characters which must not be modified or
 *  freed, or %NULL.
 **/
const char *
act_user_get_email (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->email;
}

/**
 * act_user_get_location:
 * @user: the user object to examine.
 *
 * Retrieves the location set by @user.
 *
 * Returns: (transfer none): a pointer to an array of characters which must not be modified or
 *  freed, or %NULL.
 **/
const char *
act_user_get_location (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->location;
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
 * act_user_get_locked:
 * @user: a #ActUser
 *
 * Returns whether or not the #ActUser account is locked.
 *
 * Returns: %TRUE or %FALSE
 */
gboolean
act_user_get_locked (ActUser *user)
{
        return user->locked;;
}

/**
 * act_user_get_automatic_login:
 * @user: a #ActUser
 *
 * Returns whether or not #ActUser is automatically logged in at boot time.
 *
 * Returns: %TRUE or %FALSE
 */
gboolean
act_user_get_automatic_login (ActUser *user)
{
        return user->automatic_login;
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
 * act_user_get_x_session:
 * @user: a #ActUser
 *
 * Returns the path to the configured X session for @user.
 *
 * Returns: (transfer none): a path to an icon
 */
const char *
act_user_get_x_session (ActUser *user)
{
        g_return_val_if_fail (ACT_IS_USER (user), NULL);

        return user->x_session;
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
        } else if (strcmp (key, "AccountType") == 0) {
                int new_account_type;

                new_account_type = g_value_get_int (value);
                if ((int) user->account_type != new_account_type) {
                        user->account_type = (ActUserAccountType) new_account_type;
                        g_object_notify (G_OBJECT (user), "account-type");
                }
        } else if (strcmp (key, "PasswordMode") == 0) {
                int new_password_mode;

                new_password_mode = g_value_get_int (value);
                if ((int) user->password_mode != new_password_mode) {
                        user->password_mode = (ActUserPasswordMode) new_password_mode;
                        g_object_notify (G_OBJECT (user), "password-mode");
                }
        } else if (strcmp (key, "PasswordHint") == 0) {
                const char *new_password_hint;

                new_password_hint = g_value_get_string (value);
                if (g_strcmp0 (user->password_hint, new_password_hint) != 0) {
                        g_free (user->password_hint);
                        user->password_hint = g_value_dup_string (value);
                        g_object_notify (G_OBJECT (user), "password-hint");
                }
        } else if (strcmp (key, "HomeDirectory") == 0) {
                const char *new_home_dir;

                new_home_dir = g_value_get_string (value);
                if (g_strcmp0 (user->home_dir, new_home_dir) != 0) {
                        g_free (user->home_dir);
                        user->home_dir = g_strdup (new_home_dir);
                        g_object_notify (G_OBJECT (user), "home-directory");
                }
        } else if (strcmp (key, "Shell") == 0) {
                const char *new_shell;

                new_shell = g_value_get_string (value);
                if (g_strcmp0 (user->shell, new_shell) != 0) {
                        g_free (user->shell);
                        user->shell = g_strdup (new_shell);
                        g_object_notify (G_OBJECT (user), "shell");
                }
        } else if (strcmp (key, "Email") == 0) {
                const char *new_email;

                new_email = g_value_get_string (value);
                if (g_strcmp0 (user->email, new_email) != 0) {
                        g_free (user->email);
                        user->email = g_strdup (new_email);
                        g_object_notify (G_OBJECT (user), "email");
                }
        } else if (strcmp (key, "Location") == 0) {
                const char *new_location;

                new_location = g_value_get_string (value);
                if (g_strcmp0 (user->location, new_location) != 0) {
                        g_free (user->location);
                        user->location = g_strdup (new_location);
                        g_object_notify (G_OBJECT (user), "location");
                }
        } else if (strcmp (key, "Locked") == 0) {
                gboolean new_locked_state;

                new_locked_state = g_value_get_boolean (value);
                if (new_locked_state != user->locked) {
                        user->locked = new_locked_state;
                        g_object_notify (G_OBJECT (user), "locked");
                }
        } else if (strcmp (key, "AutomaticLogin") == 0) {
                gboolean new_automatic_login_state;

                new_automatic_login_state = g_value_get_boolean (value);
                if (new_automatic_login_state != user->automatic_login) {
                        user->automatic_login = new_automatic_login_state;
                        g_object_notify (G_OBJECT (user), "automatic-login");
                }
        } else if (strcmp (key, "LoginFrequency") == 0) {
                int new_login_frequency;

                new_login_frequency = (int) g_value_get_uint64 (value);
                if ((int) user->login_frequency != (int) new_login_frequency) {
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
        } else if (strcmp (key, "XSession") == 0) {
                const char *new_x_session;

                new_x_session = g_value_get_string (value);
                if (g_strcmp0 (user->x_session, new_x_session) != 0) {
                        g_free (user->x_session);
                        user->x_session = g_value_dup_string (value);
                        g_object_notify (G_OBJECT (user), "x-session");
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
        g_assert (DBUS_IS_G_PROXY (user->object_proxy));
        g_assert (user->object_proxy == proxy);

        error = NULL;
        res = dbus_g_proxy_end_call (proxy,
                                     call,
                                     &error,
                                     dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
                                     &hash_table,
                                     G_TYPE_INVALID);
        user->get_all_call = NULL;

        if (! res) {
                g_debug ("Error calling GetAll() when retrieving properties for %s: %s",
                         user->object_path, error->message);
                g_error_free (error);
                return;
        }
        g_hash_table_foreach (hash_table, (GHFunc) collect_props, user);
        g_hash_table_unref (hash_table);

        if (!user->is_loaded) {
                set_is_loaded (user, TRUE);
        }

        g_signal_emit (user, signals[CHANGED], 0);
}

static gboolean
update_info (ActUser *user)
{
        DBusGProxyCall *call;

        g_assert (DBUS_IS_G_PROXY (user->object_proxy));

        call = dbus_g_proxy_begin_call (user->object_proxy,
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

        if (user->get_all_call != NULL) {
                dbus_g_proxy_cancel_call (user->object_proxy, user->get_all_call);
        }

        user->get_all_call = call;
        return TRUE;

failed:
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

        user->object_proxy = dbus_g_proxy_new_for_name (user->connection,
                                                        ACCOUNTS_NAME,
                                                        user->object_path,
                                                        DBUS_INTERFACE_PROPERTIES);

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

/**
 * act_user_set_email:
 * @user: the user object to alter.
 * @email: an email address
 *
 * Assigns a new email to @user.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_email (ActUser    *user,
                    const char *email)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (email != NULL);
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetEmail",
                                &error,
                                G_TYPE_STRING, email,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetEmail call failed: %s", error->message);
                g_error_free (error);
                return;
        }
}

/**
 * act_user_set_language:
 * @user: the user object to alter.
 * @language: a locale (e.g. en_US.utf8)
 *
 * Assigns a new locale for @user.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_language (ActUser    *user,
                       const char *language)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (language != NULL);
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetLanguage",
                                &error,
                                G_TYPE_STRING, language,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetLanguage call failed: %s", error->message);
                g_error_free (error);
                return;
        }
}

/**
 * act_user_set_x_session:
 * @user: the user object to alter.
 * @x_session: an x session (e.g. gnome)
 *
 * Assigns a new x session for @user.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_x_session (ActUser    *user,
                        const char *x_session)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (x_session != NULL);
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetXSession",
                                &error,
                                G_TYPE_STRING, x_session,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetXSession call failed: %s", error->message);
                g_error_free (error);
                return;
        }
}


/**
 * act_user_set_location:
 * @user: the user object to alter.
 * @location: a location
 *
 * Assigns a new location for @user.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_location (ActUser    *user,
                       const char *location)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (location != NULL);
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetLocation",
                                &error,
                                G_TYPE_STRING, location,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetLocation call failed: %s", error->message);
                g_error_free (error);
                return;
        }
}

/**
 * act_user_set_user_name:
 * @user: the user object to alter.
 * @user_name: a new user name
 *
 * Assigns a new username for @user.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_user_name (ActUser    *user,
                        const char *user_name)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (user_name != NULL);
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetUserName",
                                &error,
                                G_TYPE_STRING, user_name,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetUserName call failed: %s", error->message);
                g_error_free (error);
                return;
        }
}

/**
 * act_user_set_real_name:
 * @user: the user object to alter.
 * @real_name: a new name
 *
 * Assigns a new name for @user.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_real_name (ActUser    *user,
                        const char *real_name)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (real_name != NULL);
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetRealName",
                                &error,
                                G_TYPE_STRING, real_name,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetRealName call failed: %s", error->message);
                g_error_free (error);
                return;
        }
}

/**
 * act_user_set_icon_file:
 * @user: the user object to alter.
 * @icon_file: path to an icon
 *
 * Assigns a new icon for @user.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_icon_file (ActUser    *user,
                        const char *icon_file)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (icon_file != NULL);
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetIconFile",
                                &error,
                                G_TYPE_STRING, icon_file,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetIconFile call failed: %s", error->message);
                g_error_free (error);
                return;
        }
}

/**
 * act_user_set_account_type:
 * @user: the user object to alter.
 * @account_type: a #ActUserAccountType
 *
 * Changes the account type of @user.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_account_type (ActUser            *user,
                           ActUserAccountType  account_type)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetAccountType",
                                &error,
                                G_TYPE_INT, account_type,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetAccountType call failed: %s", error->message);
                g_error_free (error);
                return;
        }
}

static gchar
salt_char (GRand *rand)
{
        gchar salt[] = "ABCDEFGHIJKLMNOPQRSTUVXYZ"
                       "abcdefghijklmnopqrstuvxyz"
                       "./0123456789";

        return salt[g_rand_int_range (rand, 0, G_N_ELEMENTS (salt))];
}

static gchar *
make_crypted (const gchar *plain)
{
        GString *salt;
        gchar *result;
        GRand *rand;
        gint i;

        rand = g_rand_new ();
        salt = g_string_sized_new (21);

        /* SHA 256 */
        g_string_append (salt, "$6$");
        for (i = 0; i < 16; i++) {
                g_string_append_c (salt, salt_char (rand));
        }
        g_string_append_c (salt, '$');

        result = g_strdup (crypt (plain, salt->str));

        g_string_free (salt, TRUE);
        g_rand_free (rand);

        return result;
}

/**
 * act_user_set_password:
 * @user: the user object to alter.
 * @password: a password
 * @hint: a hint to help user recall password
 *
 * Changes the password of @user to @password.
 * @hint is displayed to the user if they forget the password.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_password (ActUser             *user,
                       const gchar         *password,
                       const gchar         *hint)
{
        GError *error = NULL;
        gchar *crypted;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (password != NULL);
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        crypted = make_crypted (password);
        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetPassword",
                                &error,
                                G_TYPE_STRING, crypted,
                                G_TYPE_STRING, hint,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetPassword call failed: %s", error->message);
                g_error_free (error);
        }
        memset (crypted, 0, strlen (crypted));
        g_free (crypted);
}

/**
 * act_user_set_password_mode:
 * @user: the user object to alter.
 * @password_mode: a #ActUserPasswordMode
 *
 * Changes the password of @user.  If @password_mode is
 * ACT_USER_PASSWORD_MODE_SET_AT_LOGIN then the user will
 * be asked for a new password at the next login.  If @password_mode
 * is ACT_USER_PASSWORD_MODE_NONE then the user will not require
 * a password to log in.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_password_mode (ActUser             *user,
                            ActUserPasswordMode  password_mode)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetPasswordMode",
                                &error,
                                G_TYPE_INT, (int) password_mode,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetPasswordMode call failed: %s", error->message);
                g_error_free (error);
        }
}

/**
 * act_user_set_locked:
 * @user: the user object to alter.
 * @locked: whether or not the account is locked
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_locked (ActUser  *user,
                     gboolean  locked)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetLocked",
                                &error,
                                G_TYPE_BOOLEAN, locked,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetLocked call failed: %s", error->message);
                g_error_free (error);
        }
}

/**
 * act_user_set_automatic_login:
 * @enabled: whether or not to autologin for user.
 *
 * If enabled is set to %TRUE then this user will automatically be logged in
 * at boot up time.  Only one user can be configured to auto login at any given
 * time, so subsequent calls to act_user_set_automatic_login() override previous
 * calls.
 *
 * Note this function is synchronous and ignores errors.
 **/
void
act_user_set_automatic_login (ActUser   *user,
                              gboolean  enabled)
{
        GError *error = NULL;

        g_return_if_fail (ACT_IS_USER (user));
        g_return_if_fail (DBUS_IS_G_PROXY (user->accounts_proxy));

        if (!dbus_g_proxy_call (user->accounts_proxy,
                                "SetAutomaticLogin",
                                &error,
                                G_TYPE_BOOLEAN, enabled,
                                G_TYPE_INVALID,
                                G_TYPE_INVALID)) {
                g_warning ("SetAutomaticLogin call failed: %s", error->message);
                g_error_free (error);
        }
}
