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

rule_t rules;

static bool
vm_gets_devices_when_in_focus(vm_t *vm)
{
  char *obj_path = NULL;
  gboolean v;

  if (!com_citrix_xenclient_xenmgr_find_vm_by_domid_(g_xcbus, "com.citrix.xenclient.xenmgr", "/", vm->domid, &obj_path))
    return false;

  if (!property_get_com_citrix_xenclient_xenmgr_vm_usb_auto_passthrough_(g_xcbus, "com.citrix.xenclient.xenmgr", obj_path, &v))
    return false;

  return (v == TRUE) ? true : false;
}

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

static vm_t*
vm_focused(void)
{
  int domid;

  xcdbus_input_get_focus_domid(g_xcbus, &domid);

  return vm_lookup(domid);
}

static bool
device_matches_rule(rule_t *rule, device_t *device)
{
  /* If the rule specifies a vendorid, it has to match */
  if (rule->dev_vendorid != 0 &&
      device->vendorid != rule->dev_vendorid)
    return false;
  /* If the rule specifies a deviceid, it has to match */
  if (rule->dev_deviceid != 0 &&
      device->deviceid != rule->dev_deviceid)
    return false;
  /* device->type must have at least all the bits from rule->dev_type */
  if (rule->dev_type != 0 &&
      (device->type & rule->dev_type) != rule->dev_type)
    return false;
  /* device->type must have no bit in common with rule->dev_not_type */
  if (rule->dev_not_type != 0 &&
      (device->type & rule->dev_not_type))
    return false;
  printf("device matches rule\n");

  /* Everything specified matches, we're good */
  return true;
}

static bool
vm_matches_rule(rule_t *rule, vm_t *vm)
{
  /* If the rule specifies a VM UUID it has to match */
  if (rule->vm_uuid != NULL &&
      strcmp(rule->vm_uuid, vm->uuid))
    return false;
  printf("VM matches rule\n");

  /* Everything specified matches, we're good */
  return true;
}

static rule_t*
sticky_lookup(device_t *device)
{
  struct list_head *pos;
  rule_t *rule;

  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->cmd == ALWAYS &&
        device_matches_rule(rule, device)) {
      return rule;
    }
  }

  return NULL;
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

/**
 * Check if the policy allows a given device to be assigned to a given VM
 */
bool
policy_is_allowed(device_t *device, vm_t *vm)
{
  struct list_head *pos;
  rule_t *rule;

  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    /* First match wins (or looses), ALWAYS implies ALLOW */
    xd_log(LOG_ERR, "%s\n", rule->vm_uuid);
    if (device_matches_rule(rule, device) &&
        vm_matches_rule(rule, vm))
      return (rule->cmd != DENY);
  }

  /* No match found, default to DENY. Return TRUE here to default to ALLOW */
  return false;
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
    if (vm == NULL) {
      vm = vm_focused();
      if (!vm_gets_devices_when_in_focus(vm))
        vm = NULL;
    }
  }

  property_get_com_citrix_xenclient_xenmgr_vm_domid_(g_xcbus, XENMGR, UIVM_PATH, &uivm);
  if (vm != NULL &&
      vm->domid > 0 &&
      vm->domid != uivm &&
      policy_is_allowed(device, vm))
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
  struct list_head *pos, *device_pos;
  rule_t *rule;
  device_t *device;
  int ret = 0;

  /* For all the ALWAYS rules that match the VM, assign all devices
   * that match the rule to the VM */
  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->cmd == ALWAYS && !strcmp(rule->vm_uuid, vm->uuid)) {
      list_for_each(device_pos, &devices.list) {
        device = list_entry(device_pos, device_t, list);
        if (!device_matches_rule(rule, device))
          continue;
        /* The device matches the rule, let's try to assign it */
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
          /* No need to check the policy, ALWAYS implies ALLOW */
          device->vm = vm;
          ret |= usbowls_plug_device(vm->domid, device->busid, device->devid);
        }
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
