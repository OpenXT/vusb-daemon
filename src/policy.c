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
 * @file   policy.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Tue Jul 21 12:35:02 2015
 *
 * @brief  The USB policy management
 *
 * Functions used to configure the policy for USB assignations
 */

#include "project.h"

/**
 * If this stays true, it means devices are automatically assigned to
 * the VM that currently has the focus (unless there's a sticky rule
 * for assigning it to another running VM)
 */
static bool auto_assign_to_focused_vm = true;

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

rule_t rules;

static void
dump_rules(void)
{
  struct list_head *pos;
  rule_t *rule;

  printf("----------RULES----------\n");
  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->cmd == ALWAYS)
      printf("always\n");
    else if (rule->cmd == ALLOW)
      printf("allow\n");
    else if (rule->cmd == DENY)
      printf("deny\n");
    printf("  pos    %d\n", rule->pos);
    printf("  desc   \"%s\"\n", rule->desc);
    printf("  device type=%d type!=%d vendorid=%X deviceid=%X\n",
           rule->dev_type, rule->dev_not_type, rule->dev_vendorid, rule->dev_deviceid);
    printf("  vm     uuid=%s\n", rule->vm_uuid);
  }
  printf("-------------------------\n");
}

static char*
parse_value(char *subnode_path, char *key)
{
  char *value;
  char path[128];

  sprintf(path, "%s/%s", subnode_path, key);
  if (com_citrix_xenclient_db_read_(g_xcbus, DB, DB_OBJ, path, &value))
    return value;

  return NULL;
}

static void
parse_device(char *rule_path, char *rule, rule_t *res)
{
  char **rul, **ru;
  char *value;
  char node_path[64], subnode_path[64];

  sprintf(node_path, "%s/%s", rule_path, rule);
  if (com_citrix_xenclient_db_list_(g_xcbus, DB, DB_OBJ, node_path, &rul)) {
    while (*rul != NULL) {
      if        (!strcmp(*rul, "sysattr")) {
        sprintf(subnode_path, "%s/%s", node_path, *rul);
        if (com_citrix_xenclient_db_list_(g_xcbus, DB, DB_OBJ, subnode_path, &ru)) {
          while (*ru != NULL) {
            value = parse_value(subnode_path, *ru);
            if (value != NULL) {
              xd_log(LOG_WARN, "IGNORING sysattr  %s=%s (not implemented yet)",
                     *ru, value);
            }
            ru++;
          }
        }
      } else if (!strcmp(*rul, "udevparm")) {
        sprintf(subnode_path, "%s/%s", node_path, *rul);
        if (com_citrix_xenclient_db_list_(g_xcbus, DB, DB_OBJ, subnode_path, &ru)) {
          while (*ru != NULL) {
            value = parse_value(subnode_path, *ru);
            if (value != NULL) {
              xd_log(LOG_WARN, "IGNORING udevparm %s=%s (not implemented yet)",
                     *ru, value);
            }
            ru++;
          }
        }
      } else if (!strcmp(*rul, "mouse")) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= MOUSE;
          else
            res->dev_type |= MOUSE;
        }
      } else if (!strcmp(*rul, "keyboard")) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= KEYBOARD;
          else
            res->dev_type |= KEYBOARD;
        }
      } else if (!strcmp(*rul, "game_controller")) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= GAME_CONTROLLER;
          else
            res->dev_type |= GAME_CONTROLLER;
        }
      } else if (!strcmp(*rul, "mass_storage")) {
        value = parse_value(node_path, *rul);
        if (value != NULL) {
          if (*value == '0')
            res->dev_not_type |= MASS_STORAGE;
          else
            res->dev_type |= MASS_STORAGE;
        }
      } else if (!strcmp(*rul, "vendor_id")) {
        value = parse_value(node_path, *rul);
        if (value != NULL)
          res->dev_vendorid = strtol(value, NULL, 16);
      } else if (!strcmp(*rul, "device_id")) {
        value = parse_value(node_path, *rul);
        if (value != NULL)
          res->dev_deviceid = strtol(value, NULL, 16);
      } else xd_log(LOG_ERR, "Unknown Device attribute %s", *rul);
      rul++;
    }
  }
}

static void
parse_vm(char *rule_path, char *rule, rule_t *res)
{
  char **rul;
  char node_path[64];

  sprintf(node_path, "%s/%s", rule_path, rule);
  if (com_citrix_xenclient_db_list_(g_xcbus, DB, DB_OBJ, node_path, &rul)) {
    while (*rul != NULL) {
      if (!strcmp(*rul, "uuid")) {
        res->vm_uuid = parse_value(node_path, *rul);
      } else {
        xd_log(LOG_ERR, "Unknown VM attribute %s", *rul);
      }
      rul++;
    }
  }
}

static rule_t*
parse_rule(char *rule_node)
{
  char **rule;
  char rule_path[32];
  char *value;
  rule_t* res;

  res = malloc(sizeof(rule_t));
  memset(res, 0, sizeof(rule_t));
  res->pos = strtol(rule_node, NULL, 10);
  sprintf(rule_path, "/usb-rules/%s", rule_node);
  if (com_citrix_xenclient_db_list_(g_xcbus, DB, DB_OBJ, rule_path, &rule)) {
    while (*rule != NULL) {
      if        (!strcmp(*rule, "command")) {
        value = parse_value(rule_path, *rule);
        if (value != NULL) {
          if (!strcmp(value, "always"))
            res->cmd = ALWAYS;
          else if (!strcmp(value, "allow"))
            res->cmd = ALLOW;
          else if (!strcmp(value, "deny"))
            res->cmd = DENY;
          else xd_log(LOG_ERR, "Unknown command %s", value);
        }
      } else if (!strcmp(*rule, "description")) {
        res->desc = parse_value(rule_path, *rule);
      } else if (!strcmp(*rule, "device")) {
        parse_device(rule_path, *rule, res);
      } else if (!strcmp(*rule, "vm")) {
        parse_vm(rule_path, *rule, res);
      } else {
        xd_log(LOG_ERR, "Unknown rule attribute %s", *rule);
      }
      rule++;
    }
  }

  return res;
}

static void
add_rule_to_list(rule_t *new_rule)
{
  struct list_head *pos;
  rule_t *rule = NULL;

  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->pos > new_rule->pos)
      break;
  }
  if (rule != NULL && rule->pos > new_rule->pos)
    list_add(&new_rule->list, &rule->list);
  else
    list_add_tail(&new_rule->list, &rules.list);
}

static void
policy_read_db(void)
{
  char **rule_nodes;
  rule_t *rule;

  if (com_citrix_xenclient_db_list_(g_xcbus, DB, DB_OBJ, "/usb-rules", &rule_nodes)) {
    while (*rule_nodes != NULL) {
      rule = parse_rule(*rule_nodes);
      if (rule != NULL)
        add_rule_to_list(rule);
      rule_nodes++;
    }
  }
}

static void
db_write_rule_key(int pos, char *key, char *value)
{
  char path[128];

  sprintf(path, "/usb-rules/%d/%s", pos, key);
  com_citrix_xenclient_db_write_(g_xcbus, DB, DB_OBJ, path, value);
}

static void
policy_write_db(void)
{
  struct list_head *pos;
  rule_t *rule = NULL;
  char value[5];

  com_citrix_xenclient_db_rm_(g_xcbus, DB, DB_OBJ, "/usb-rules");

  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->desc != NULL)
      db_write_rule_key(rule->pos, "description", rule->desc);
    if (rule->cmd == ALWAYS)
      db_write_rule_key(rule->pos, "command", "always");
    else if (rule->cmd == ALLOW)
      db_write_rule_key(rule->pos, "command", "allow");
    else if (rule->cmd == DENY)
      db_write_rule_key(rule->pos, "command", "deny");
    if (rule->dev_type != 0) {
      if (rule->dev_type & KEYBOARD)
        db_write_rule_key(rule->pos, "device/keyboard", "1");
      if (rule->dev_type & MOUSE)
        db_write_rule_key(rule->pos, "device/mouse", "1");
      if (rule->dev_type & GAME_CONTROLLER)
        db_write_rule_key(rule->pos, "device/game_controller", "1");
      if (rule->dev_type & MASS_STORAGE)
        db_write_rule_key(rule->pos, "device/mass_storage", "1");
    }
    if (rule->dev_not_type != 0) {
      if (rule->dev_not_type & KEYBOARD)
        db_write_rule_key(rule->pos, "device/keyboard", "0");
      if (rule->dev_not_type & MOUSE)
        db_write_rule_key(rule->pos, "device/mouse", "0");
      if (rule->dev_not_type & GAME_CONTROLLER)
        db_write_rule_key(rule->pos, "device/game_controller", "0");
      if (rule->dev_not_type & MASS_STORAGE)
        db_write_rule_key(rule->pos, "device/mass_storage", "0");
    }
    if (rule->dev_vendorid != 0) {
      sprintf(value, "%04X", rule->dev_vendorid);
      db_write_rule_key(rule->pos, "device/vendor_id", value);
    }
    if (rule->dev_deviceid != 0) {
      sprintf(value, "%04X", rule->dev_deviceid);
      db_write_rule_key(rule->pos, "device/device_id", value);
    }
    if (rule->vm_uuid != NULL)
      db_write_rule_key(rule->pos, "vm/uuid", rule->vm_uuid);
  }
}

/**
 * Create a new sticky rule using a device and its currently assigned
 * VM, then rewrite the rules to the database
 *
 * @param dev The device single ID
 *
 * @return 0 if the device was found and assigned to a VM, -1 otherwise
 */
int
policy_set_sticky(int dev)
{
  int busid, devid;
  device_t *device;
  struct list_head *pos;
  rule_t *rule = NULL;
  rule_t *new_rule;

  makeBusDevPair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL || device->vm == NULL)
    return -1;
  new_rule = malloc(sizeof(rule_t));
  memset(new_rule, 0, sizeof(rule_t));
  new_rule->pos = 1000;
  new_rule->cmd = ALWAYS;
  new_rule->dev_vendorid = device->vendorid;
  new_rule->dev_deviceid = device->deviceid;
  new_rule->vm_uuid = malloc(UUID_LENGTH);
  strcpy(new_rule->vm_uuid, device->vm->uuid);
  new_rule->desc = malloc(strlen(device->shortname));
  strcpy(new_rule->desc, device->shortname);
  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->pos <= 1000)
      new_rule->pos = rule->pos - 1;
    break;
  }
  list_add(&new_rule->list, &rules.list);

  dump_rules();
  policy_write_db();

  return 0;
}

static rule_t*
sticky_lookup(device_t *device)
{
  struct list_head *pos;
  rule_t *rule;

  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    /* IMPORTANT TODO: compare only relevant fields */
    if (rule->cmd == ALWAYS &&
        rule->dev_vendorid == device->vendorid &&
        rule->dev_deviceid == device->deviceid) {
      return rule;
    }
  }

  return NULL;
}

/**
 * Delete a sticky rule matching a device. On success, dump the rules
 * to the database
 *
 * @param dev The device single ID
 *
 * @return 0 if the device was found, -1 otherwise
 */
int
policy_unset_sticky(int dev)
{
  int busid, devid;
  device_t *device;
  rule_t *rule;

  makeBusDevPair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL)
    return -1;
  rule = sticky_lookup(device);
  if (rule == NULL)
    return -1;
  list_del(&rule->list);
  dump_rules();
  policy_write_db();

  return 0;
}

/**
 * Search for a sticky rule matching a device, and return the
 * corresponding UUID
 *
 * @param dev The device single ID
 *
 * @return The UUID if a sticky rule was found, NULL otherwise
 */
char*
policy_get_sticky_uuid(int dev)
{
  int busid, devid;
  device_t *device;
  rule_t *rule;

  makeBusDevPair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL)
    return NULL;
  rule = sticky_lookup(device);
  if (rule != NULL)
    return rule->vm_uuid;
  else
    return NULL;
}

static vm_t*
vm_focused(void)
{
  int domid;

  xcdbus_input_get_focus_domid(g_xcbus, &domid);

  return vm_lookup(domid);
}

/**
 * This function should be called when a new device is plugged.
 * It will assign the device to a VM according to policy.
 *
 * @param device A pointer to the device that was just plugged
 *
 * @return 1 if the device didn't get plugged to anything, the result
 *         of usbowls_plug_device otherwise.
 */
int
policy_auto_assign_new_device(device_t *device)
{
  rule_t *rule;
  vm_t *vm = NULL;
  int uivm;

  /* If there's a sticky rule for the device, assign the the
   * corresponding VM (if it's running). If there's no sticky rule
   * for the device, consider assigning it to the focused VM */
  rule = sticky_lookup(device);
  if (rule != NULL) {
    vm = vm_lookup_by_uuid(rule->vm_uuid);
  } else {
    if (vm == NULL && auto_assign_to_focused_vm)
      vm = vm_focused();
  }

  property_get_com_citrix_xenclient_xenmgr_vm_domid_(g_xcbus, XENMGR, UIVM_PATH, &uivm);
  if (vm != NULL && vm->domid > 0 && vm->domid != uivm)
  {
    int res;

    device->vm = vm;
    res = usbowls_plug_device(vm->domid, device->busid, device->devid);
    if (res != 0)
      device->vm = NULL;
    return res;
  }

  return 1;
}

/**
 * Iterate over all the sticky rules that match the VM, and assign the
 * corresponding devices to it
 *
 * @param vm The VM that just started
 *
 * @return 0 for success, -1 if anything went wrong
 */
int
policy_auto_assign_devices_to_new_vm(vm_t *vm)
{
  struct list_head *pos;
  rule_t *rule;
  device_t *device;
  int ret = 0;

  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->cmd == ALWAYS && !strcmp(rule->vm_uuid, vm->uuid)) {
      device = device_lookup_by_attributes(rule->dev_vendorid,
                                           rule->dev_deviceid,
                                           NULL);
      if (device == NULL) {
        /* The device is not there right now, moving on */
        continue;
      }
      if (device->vm != NULL) {
        if (device->vm != vm)
        {
          xd_log(LOG_ERR, "An always-assign device is assigned to another VM, this shouldn't happen!");
          ret = -1;
          continue;
        } else {
          /* The device is already assigned to the right VM */
          continue;
        }
      } else {
        /* The device is not assigned, as expected, plug it to its VM */
        device->vm = vm;
        ret |= usbowls_plug_device(vm->domid, device->busid, device->devid);
      }
    }
  }

  return ret;
}

/**
 * Initialize the policy bits
 *
 * @return 0 if everything went fine, -1 if there was an error reading
 * the policy from the database.
 */
int
policy_init(void)
{
  INIT_LIST_HEAD(&rules.list);

  policy_read_db();
  dump_rules();

  return 0;
}
