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

#ifndef   	POLICY_H_
# define   	POLICY_H_

enum command {
  ALWAYS,
  ALLOW,
  DENY
};

#define KEYBOARD        0x1
#define MOUSE           0x2
#define GAME_CONTROLLER 0x4
#define MASS_STORAGE    0x8

typedef struct {
  struct list_head list;
  int pos;
  enum command cmd;
  char *desc;
  int dev_type;
  int dev_not_type;
  int dev_vendorid;
  int dev_deviceid;
  char *vm_uuid;
} rule_t;

#endif 	    /* !POLICY_H_ */
