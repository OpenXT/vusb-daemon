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
 * @file   policy.h
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Thu Jul 30 13:25:52 2015
 *
 * @brief  The policy-related declarations
 *
 * Those declarations are defined here instead of project.h because
 * db.c, which doesn't include project.h, needs them
 */

#ifndef   	POLICY_H_
# define   	POLICY_H_

/**
 * @brief Policy rule command
 */
enum command {
  ALWAYS,                 /**< Always plug device to VM. implies ALLOW */
  ALLOW,                  /**< Allow device to be plugged to VM */
  DENY                    /**< Deny device to be plugged to VM */
};

#define KEYBOARD        0x1     /**< Keyboard device type */
#define MOUSE           0x2     /**< Mouse device type */
#define GAME_CONTROLLER 0x4     /**< Game controller device type */
#define MASS_STORAGE    0x8     /**< Mass storage device type */
#define OPTICAL         0x10    /**< Optical (cd-rom) device type */

/**
 * @brief Policy rule structure
 *
 * This is used to handle the list of policy rules
 */
typedef struct {
  struct list_head list; /**< Linux-kernel-style list item */
  int pos;               /**< Rule position */
  enum command cmd;      /**< Rule "command" (always/allow/deny) */
  char *desc;            /**< Rule description */
  int dev_type;          /**< Device type (OR-ed types that must all match) */
  int dev_not_type;      /**< Device forbidden type (none must match) */
  int dev_vendorid;      /**< Device vendorid, or 0 for none */
  int dev_deviceid;      /**< Device deviceid, or 0 for none */
  char **dev_sysattrs;   /**< List of key value pairs for the udev sysattrs */
  char **dev_properties; /**< List of key value pairs for the udev properties */
  char *vm_uuid;         /**< VM UUID */
} rule_t;

#endif 	    /* !POLICY_H_ */
