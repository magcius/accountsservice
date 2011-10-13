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

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <grp.h>

#include <syslog.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <polkit/polkit.h>

#include "util.h"


static gchar *
_polkit_subject_get_cmdline (PolkitSubject *subject, gint *pid, gint *uid)
{
  PolkitSubject *process;
  gchar *ret;
  gchar *filename;
  gchar *contents;
  gsize contents_len;
  GError *error;
  guint n;

  g_return_val_if_fail (subject != NULL, NULL);

  error = NULL;

  ret = NULL;
  process = NULL;
  filename = NULL;
  contents = NULL;

  if (POLKIT_IS_UNIX_PROCESS (subject))
   {
      process = g_object_ref (subject);
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject),
                                                         NULL,
                                                         &error);
      if (process == NULL)
        {
          g_warning ("Error getting process for system bus name `%s': %s",
                     polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject)),
                     error->message);
          g_error_free (error);
          goto out;
        }
    }
  else
    {
      g_warning ("Unknown subject type passed to guess_program_name()");
      goto out;
    }

  *pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (process));
  *uid = polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (process));

  filename = g_strdup_printf ("/proc/%d/cmdline", *pid);

  if (!g_file_get_contents (filename,
                            &contents,
                            &contents_len,
                            &error))
    {
      g_warning ("Error openeing `%s': %s",
                 filename,
                 error->message);
      g_error_free (error);
      goto out;
    }
  /* The kernel uses '\0' to separate arguments - replace those with a space. */
  for (n = 0; n < contents_len - 1; n++)
    {
      if (contents[n] == '\0')
        contents[n] = ' ';
    }

  ret = g_strdup (contents);
  g_strstrip (ret);

 out:
  g_free (filename);
  g_free (contents);
  if (process != NULL)
    g_object_unref (process);
  return ret;
}

void
sys_log (DBusGMethodInvocation *context,
         const gchar           *format,
                                ...)
{
        va_list args;
        gchar *msg;

        va_start (args, format);
        msg = g_strdup_vprintf (format, args);
        va_end (args);

        if (context) {
                PolkitSubject *subject;
                gchar *cmdline;
                gchar *id;
                gint pid = 0;
                gint uid = 0;
                gchar *tmp;

                subject = polkit_system_bus_name_new (dbus_g_method_get_sender (context));
                id = polkit_subject_to_string (subject);
                cmdline = _polkit_subject_get_cmdline (subject, &pid, &uid);

                if (cmdline == NULL) {
                        tmp = g_strdup_printf ("request by %s: %s", id, msg);
                }
                else {
                        tmp = g_strdup_printf ("request by %s [%s pid:%d uid:%d]: %s", id, cmdline, pid, uid, msg);
                }

                g_free (msg);
                msg = tmp;

                g_free (id);
                g_free (cmdline);
                g_object_unref (subject);
        }

        syslog (LOG_NOTICE, "%s", msg);

        g_free (msg);
}

static void
get_caller_loginuid (DBusGMethodInvocation *context, gchar *loginuid, gint size)
{
        PolkitSubject *subject;
        gchar *cmdline;
        gint pid;
        gint uid;
        gchar *path;
        gchar *buf;

        subject = polkit_system_bus_name_new (dbus_g_method_get_sender (context));
        cmdline = _polkit_subject_get_cmdline (subject, &pid, &uid);
        g_free (cmdline);
        g_object_unref (subject);

        path = g_strdup_printf ("/proc/%d/loginuid", pid);
        if (g_file_get_contents (path, &buf, NULL, NULL)) {
                strncpy (loginuid, buf, size);
                g_free (buf);
        }
        else {
                g_snprintf (loginuid, size, "%d", uid);
        }

        g_free (path);
}

static void
setup_loginuid (gpointer data)
{
        const char *id = data;
        int fd;

        fd = open ("/proc/self/loginuid", O_WRONLY);
        write (fd, id, strlen (id));
        close (fd);
}

gboolean
spawn_with_login_uid (DBusGMethodInvocation  *context,
                      gchar                  *argv[],
                      GError                **error)
{
        GError *local_error;
        gchar loginuid[20];
        gchar *std_err;
        gint status;

        get_caller_loginuid (context, loginuid, 20);

        local_error = NULL;
        std_err = NULL;

        if (!g_spawn_sync (NULL, argv, NULL, 0, setup_loginuid, loginuid, NULL, &std_err, &status, &local_error)) {
                g_propagate_error (error, local_error);
                g_free (std_err);
                return FALSE;
        }

        if (WEXITSTATUS (status) != 0) {
                g_set_error (error,
                             G_SPAWN_ERROR,
                             G_SPAWN_ERROR_FAILED,
                             "%s returned an error (%d): %s",
                             argv[0], WEXITSTATUS(status), std_err);
                g_free (std_err);
                return FALSE;
        }

        g_free (std_err);

        return TRUE;
}

gint
get_user_groups (const gchar  *user,
                 gid_t         group,
                 gid_t       **groups)
{
        gint res;
        gint ngroups;

        ngroups = 0;
        res = getgrouplist (user, group, NULL, &ngroups);

        g_debug ("user %s has %d groups\n", user, ngroups);
        *groups = g_new (gid_t, ngroups);
        res = getgrouplist (user, group, *groups, &ngroups);

        return res;
}


gboolean
get_caller_uid (DBusGMethodInvocation *context, gint *uid)
{
        PolkitSubject *subject;
        PolkitSubject *process;

        subject = polkit_system_bus_name_new (dbus_g_method_get_sender (context));
        process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject), NULL, NULL);
        if (!process) {
                g_object_unref (subject);
                return FALSE;
        }

        *uid = polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (process));

        g_object_unref (subject);
        g_object_unref (process);

        return TRUE;
}
