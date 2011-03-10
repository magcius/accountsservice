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
#include <stdarg.h>
#include <locale.h>
#include <libintl.h>
#include <syslog.h>

#include <glib.h>
#include <glib/gi18n.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "daemon.h"

#define NAME_TO_CLAIM "org.freedesktop.Accounts"

static GMainLoop *loop;

static void
name_lost (DBusGProxy  *system_bus_proxy,
           const gchar *name_which_was_lost,
           gpointer     user_data)
{
        g_debug ("got NameLost, exiting");
        g_main_loop_quit (loop);
}

static gboolean
acquire_name_on_proxy (DBusGProxy *system_bus_proxy,
                       gboolean    replace)
{
        GError *error;
        guint result;
        gboolean res;
        gboolean ret;
        guint flags;

        ret = FALSE;

        flags = DBUS_NAME_FLAG_ALLOW_REPLACEMENT;
        if (replace)
                flags |= DBUS_NAME_FLAG_REPLACE_EXISTING;

        error = NULL;
        res = dbus_g_proxy_call (system_bus_proxy,
                                 "RequestName",
                                 &error,
                                 G_TYPE_STRING,
                                 NAME_TO_CLAIM,
                                 G_TYPE_UINT,
                                 flags,
                                 G_TYPE_INVALID,
                                 G_TYPE_UINT,
                                 &result,
                                 G_TYPE_INVALID);
        if (!res) {
                if (error != NULL) {
                        g_warning ("Failed to acquire %s: %s",
                                   NAME_TO_CLAIM, error->message);
                        g_error_free (error);
                }
                else {
                        g_warning ("Failed to acquire %s", NAME_TO_CLAIM);
                }
                goto out;
        }

        if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
                if (error != NULL) {
                        g_warning ("Failed to acquire %s: %s",
                                   NAME_TO_CLAIM, error->message);
                        g_error_free (error);
                }
                else {
                        g_warning ("Failed to acquire %s", NAME_TO_CLAIM);
                }
                goto out;
        }

        dbus_g_proxy_add_signal (system_bus_proxy, "NameLost",
                                 G_TYPE_STRING, G_TYPE_INVALID);
        dbus_g_proxy_connect_signal (system_bus_proxy, "NameLost",
                                     G_CALLBACK (name_lost), NULL, NULL);
        ret = TRUE;

 out:
        return ret;
}

static gboolean debug;

static void
log_handler (const gchar   *domain,
             GLogLevelFlags level,
             const gchar   *message,
             gpointer       data)
{
        /* filter out DEBUG messages if debug isn't set */
        if ((level & G_LOG_LEVEL_MASK) == G_LOG_LEVEL_DEBUG && !debug)
                return;

        g_log_default_handler (domain, level, message, data);
}

int
main (int argc, char *argv[])
{
        Daemon *daemon;
        DBusGConnection *bus;
        DBusGProxy *system_bus_proxy;
        GError *error;
        gint ret;
        GOptionContext *context;
        static gboolean replace;
        static gboolean show_version;
        static GOptionEntry entries[] = {
                { "version", 0, 0, G_OPTION_ARG_NONE, &show_version, N_("Output version information and exit"), NULL },
                { "replace", 0, 0, G_OPTION_ARG_NONE, &replace, N_("Replace existing instance"), NULL },
                { "debug", 0, 0, G_OPTION_ARG_NONE, &debug, N_("Enable debugging code"), NULL },

                { NULL }
        };

        ret = 1;
        error = NULL;

        setlocale (LC_ALL, "");
        bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

        g_type_init ();

        if (!g_setenv ("GIO_USE_VFS", "local", TRUE)) {
                g_warning ("Couldn't set GIO_USE_GVFS");
                goto out;
        }

        context = g_option_context_new ("");
        g_option_context_set_translation_domain (context, GETTEXT_PACKAGE);
        g_option_context_set_summary (context, _("Provides D-Bus interfaces for querying and manipulating\nuser account information."));
        g_option_context_add_main_entries (context, entries, NULL);
        error = NULL;
        if (!g_option_context_parse (context, &argc, &argv, &error)) {
                g_warning ("%s", error->message);
                g_error_free (error);
                goto out;
        }
        g_option_context_free (context);

        if (show_version) {
                g_print ("accounts-daemon " VERSION "\n");
                ret = 0;
                goto out;
        }

        g_log_set_default_handler (log_handler, NULL);

        bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
                g_warning ("Could not connect to system bus: %s", error->message);
                g_error_free (error);
                goto out;
        }

        system_bus_proxy = dbus_g_proxy_new_for_name (bus,
                                                      DBUS_SERVICE_DBUS,
                                                      DBUS_PATH_DBUS,
                                                      DBUS_INTERFACE_DBUS);
        if (system_bus_proxy == NULL) {
                g_warning ("Could not construct system_bus_proxy object");
                goto out;
        }

        if (!acquire_name_on_proxy (system_bus_proxy, replace)) {
                g_warning ("Could not acquire name");
                goto out;
        }

        daemon = daemon_new ();

        if (daemon == NULL)
                goto out;

        openlog ("accounts-daemon", LOG_PID, LOG_DAEMON);
        syslog (LOG_INFO, "started daemon version %s", VERSION);
        closelog ();
        openlog ("accounts-daemon", 0, LOG_AUTHPRIV);

        loop = g_main_loop_new (NULL, FALSE);

        g_debug ("entering main loop\n");
        g_main_loop_run (loop);

        g_main_loop_unref (loop);

        ret = 0;

 out:
        return ret;
}

