/*
 * Copyright (c) 2015 Jed Lejosne <lejosnej@ainfosec.com>
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

/**
 * @file   db.h
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Thu Jul 30 13:41:28 2015
 *
 * @brief  Database interaction declarations
 *
 * This should be included in any project that needs to interract with
 * the policy.
 */

#ifndef   	DB_H_
# define   	DB_H_

#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <syslog.h>
#include "rpcgen/db_client.h"
#include "list.h"
#include "policy.h"

#define DB          "com.citrix.xenclient.db"
#define DB_OBJ      "/"

void db_dbus_init(xcdbus_conn_t *xcbus_conn);
void db_read_policy(rule_t *rules);
void db_write_policy(rule_t *rules);

#endif 	    /* !DB_H_ */
