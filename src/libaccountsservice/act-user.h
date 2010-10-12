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

/*
 * Facade object for user data, owned by ActUserManager
 */

#ifndef __ACT_USER_H__
#define __ACT_USER_H__

#include <sys/types.h>
#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define ACT_TYPE_USER (act_user_get_type ())
#define ACT_USER(object) (G_TYPE_CHECK_INSTANCE_CAST ((object), ACT_TYPE_USER, ActUser))
#define ACT_IS_USER(object) (G_TYPE_CHECK_INSTANCE_TYPE ((object), ACT_TYPE_USER))

typedef struct _ActUser ActUser;
typedef struct _ActUserClass ActUserClass;

GType          act_user_get_type                  (void) G_GNUC_CONST;

const char    *act_user_get_object_path           (ActUser *user);

gulong         act_user_get_uid                   (ActUser   *user);
const char    *act_user_get_user_name             (ActUser   *user);
const char    *act_user_get_real_name             (ActUser   *user);
guint          act_user_get_num_sessions          (ActUser   *user);
gboolean       act_user_is_logged_in              (ActUser   *user);
gulong         act_user_get_login_frequency       (ActUser   *user);
const char    *act_user_get_icon_file             (ActUser   *user);
const char    *act_user_get_primary_session_id    (ActUser   *user);

gint           act_user_collate                   (ActUser   *user1,
                                                   ActUser   *user2);
gboolean       act_user_is_loaded                 (ActUser   *user);

G_END_DECLS

#endif /* __ACT_USER_H__ */
