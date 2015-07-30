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
  db_write_policy(&rules);

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
  db_write_policy(&rules);

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

  db_dbus_init(g_xcbus);
  db_read_policy(&rules);
  dump_rules();

  return 0;
}
