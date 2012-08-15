/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2007 William Jon McCann <mccann@jhu.edu>
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

#ifndef __ACT_TYPES_H__
#define __ACT_TYPES_H__

G_BEGIN_DECLS

typedef enum {
        ACT_USER_ACCOUNT_TYPE_STANDARD,
        ACT_USER_ACCOUNT_TYPE_ADMINISTRATOR,
} ActUserAccountType;

typedef enum {
        ACT_USER_PASSWORD_MODE_REGULAR,
        ACT_USER_PASSWORD_MODE_SET_AT_LOGIN,
        ACT_USER_PASSWORD_MODE_NONE,
} ActUserPasswordMode;

G_END_DECLS

#endif
