/*
 * Copyright (c) 2015 Assured Information Security, Inc.
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

  if (!property_get_com_citrix_xenclient_xenmgr_vm_usb_auto_passthrough_(g_xcbus, "com.citrix.xenclient.xenmgr", obj_path, &v)) {
    g_free(obj_path);
    return false;
  }

  g_free(obj_path);

  return (v == TRUE) ? true : false;
}

rule_t*
policy_get_rule(uint16_t position)
{
  struct list_head *pos;
  rule_t *rule = NULL;

  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);

    if (rule->pos == position) break;

    if (rule->pos > position) {
      rule = NULL;
      break;
    }
  }

  return rule;
}

int
policy_remove_rule(uint16_t position)
{
  struct list_head *pos, *tmp;
  rule_t *rule = NULL;

  list_for_each_safe(pos, tmp, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->pos == position) {
      list_del(&rule->list);
      xd_log(LOG_INFO, "Removed USB policy rule %d", position);
      policy_free_rule(rule);
      db_write_policy(&rules);
      return 1;
    }

    if (rule->pos > position) break;
  }

  xd_log(LOG_INFO,
      "Attempted to remove USB policy rule %d, but rule was not found",
      position);

  return 0;
}

void
policy_list_rules(uint16_t **list, size_t *size)
{
  struct list_head *pos;
  rule_t *rule;
  uint16_t index = 0;
  int rule_count = 0;
  uint16_t *rule_indices = NULL;

  list_for_each(pos, &rules.list) {
    rule_count++;
  }
  *size = rule_count;
  if (rule_count == 0) return;

  rule_indices = (uint16_t *)malloc(sizeof(uint16_t) * rule_count);
  list_for_each(pos, &rules.list)
  {
    rule = list_entry(pos, rule_t, list);
    if (rule != NULL)
    {
      rule_indices[index] = rule->pos;
    }
    index++;
  }
  *list = rule_indices;
}

static void
dump_rules(void)
{
  struct list_head *pos;
  rule_t *rule;
  char **pairs;

  printf("----------RULES----------\n");
  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->cmd == ALWAYS)
      printf("always\n");
    else if (rule->cmd == DEFAULT)
      printf("default\n");
    else if (rule->cmd == ALLOW)
      printf("allow\n");
    else if (rule->cmd == DENY)
      printf("deny\n");
    printf("  pos        %d\n", rule->pos);
    printf("  desc       \"%s\"\n", rule->desc);
    printf("  device     type=%d type!=%d vendorid=%X deviceid=%X\n serial=%s\n",
           rule->dev_type, rule->dev_not_type, rule->dev_vendorid, rule->dev_deviceid, rule->dev_serial);
    pairs = rule->dev_sysattrs;
    if (pairs != NULL) {
      printf("  sysattrs  ");
      while (*pairs != NULL) {
        printf(" %s=\"%s\"", *pairs, *(pairs + 1));
        pairs += 2;
      }
      printf("\n");
    }
    pairs = rule->dev_properties;
    if (pairs != NULL) {
      printf("  properties");
      while (*pairs != NULL) {
        printf(" %s=\"%s\"", *pairs, *(pairs + 1));
        pairs += 2;
      }
      printf("\n");
    }
    printf("  vm         uuid=%s\n", rule->vm_uuid);
  }
  printf("-------------------------\n");
}

static vm_t*
vm_focused(void)
{
  int domid;

  com_citrix_xenclient_input_get_focus_domid_(g_xcbus, INPUT, INPUT_OBJ, &domid);

  return vm_lookup(domid);
}

static bool
device_matches_udev_rule(rule_t *rule, device_t *device)
{
  char **pairs;

  if (rule->dev_sysattrs != NULL) {
    pairs = rule->dev_sysattrs;
    while (*pairs != NULL) {
      if (! udev_device_tree_match_sysattr(device->udev,
            pairs[0],
            pairs[1]))
        return false;

      pairs += 2;
    }
  }

  if (rule->dev_properties != NULL) {
    pairs = rule->dev_properties;
    while (*pairs != NULL) {
      if (! udev_device_tree_match_property(device->udev,
            pairs[0],
            pairs[1]))
        return false;

      pairs += 2;
    }
  }

  return true;
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
  /* If the rule specifies a serial, it has to match */
  if (rule->dev_serial != NULL) {
    /* If the device does not have a serial, it does not match */
    if (device->serial == NULL)
      return false;
    /* Ensure the rule and device serials match */
    else if (strcmp(rule->dev_serial,device->serial) != 0)
      return false;
  }
  /* device->type must have at least all the bits from rule->dev_type */
  if (rule->dev_type != 0 &&
      (device->type & rule->dev_type) != rule->dev_type)
    return false;
  /* device->type must have no bit in common with rule->dev_not_type */
  if (rule->dev_not_type != 0 &&
      (device->type & rule->dev_not_type))
    return false;

  /* Everything specified matches, we're good */
  return device_matches_udev_rule(rule, device);
}

static bool
vm_matches_rule(rule_t *rule, vm_t *vm)
{
  /* If the rule specifies a VM UUID it has to match */
  if (rule->vm_uuid != NULL &&
      strcmp(rule->vm_uuid, vm->uuid))
    return false;

  /* Everything specified matches, we're good */
  return true;
}

static rule_t*
rule_lookup(device_t *device, enum command cmd)
{
  struct list_head *pos;
  rule_t *rule;

  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->cmd == cmd &&
        device_matches_rule(rule, device)) {
      return rule;
    }
  }

  return NULL;
}

static rule_t*
sticky_lookup(device_t *device)
{
  return rule_lookup(device, ALWAYS);
}

static rule_t*
default_lookup(device_t *device)
{
  return rule_lookup(device, DEFAULT);
}

void
policy_add_rule(rule_t *new_rule)
{
  struct list_head *pos;
  rule_t *rule_tmp = NULL;

  if (new_rule == NULL) return;

  list_for_each(pos, &rules.list) {
    rule_tmp = list_entry(pos, rule_t, list);
    if (rule_tmp->pos >= new_rule->pos)
      break;
  }
  if (rule_tmp == NULL) {
    list_add(&new_rule->list, &rules.list);
    xd_log(LOG_INFO,
        "Rule %d added, as the only rule in the set",
        new_rule->pos);
  }
  else if (new_rule->pos > rule_tmp->pos) {
    list_add(&new_rule->list, &rule_tmp->list);
    xd_log(LOG_INFO,
        "New rule %d added",
        new_rule->pos);
  }
  else if (rule_tmp->pos == new_rule->pos) {
    //list_replace(&rule_tmp->list, &new_rule->list);
    struct list_head *old, *new;

    old = &rule_tmp->list;
    new = &new_rule->list;

    new->next = old->next;
    new->next->prev = new;
    new->prev = old->prev;
    new->prev->next = new;

    xd_log(LOG_INFO,
        "Rule %d added, replacing an existing rule",
        new_rule->pos);

   /* Free replaced rule */
    policy_free_rule(rule_tmp);
  }
  else {
    list_add_tail(&new_rule->list, &rule_tmp->list);
    xd_log(LOG_INFO,
        "New rule %d added at end of list",
        new_rule->pos);
  }

  db_write_policy(&rules);
}

/**
 * Create a new sticky rule using a device and its currently assigned
 * VM, then rewrite the rules to the database
 *
 * @param dev The device single ID
 *
 * @return
 *  0 if the device was found and assigned to a VM,
 *  1 if the device is ambiguous,
 *  -1 otherwise
 */
int
policy_set_sticky(int dev)
{
  int busid, devid;
  device_t *device;
  struct list_head *pos;
  rule_t *rule = NULL;
  rule_t *new_rule;

  device_make_bus_dev_pair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL || device->vm == NULL)
    return -1;
  /* Do not set sticky for ambiguous devices */
  if (device_is_ambiguous(device)) {
    xd_log(LOG_INFO,
        "Not setting sticky for device: Bus=%d Dev=%d",
        busid,
        devid);
    return 1;
  }
  new_rule = malloc(sizeof(rule_t));
  memset(new_rule, 0, sizeof(rule_t));
  new_rule->pos = 1000;
  new_rule->cmd = ALWAYS;
  new_rule->dev_vendorid = device->vendorid;
  new_rule->dev_deviceid = device->deviceid;
  if (device->serial != NULL)
    new_rule->dev_serial = device->serial;
  new_rule->vm_uuid = malloc(UUID_LENGTH);
  strcpy(new_rule->vm_uuid, device->vm->uuid);
  new_rule->desc = malloc(strlen(device->shortname) + 1);
  strcpy(new_rule->desc, device->shortname);
  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if (rule->pos <= 1000)
      new_rule->pos = rule->pos - 1;
    break;
  }
  xd_log(LOG_INFO,
      "Created automatic assignment rule [%d] for device [VID=%04X, PID=%04X, Serial=%s] to VM [UUID=%s]",
      new_rule->pos,
      device->vendorid,
      device->deviceid,
      device->serial,
      new_rule->vm_uuid);
  list_add(&new_rule->list, &rules.list);

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

  device_make_bus_dev_pair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL)
    return -1;
  rule = sticky_lookup(device);
  if (rule == NULL)
    return -1;
  list_del(&rule->list);
  xd_log(LOG_INFO, "Policy %d removed", rule->pos);
  policy_free_rule(rule);
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

  device_make_bus_dev_pair(dev, &busid, &devid);
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
policy_is_allowed(device_t *device, vm_t *vm, rule_t **rule_ptr)
{
  struct list_head *pos;
  rule_t *rule;

  list_for_each(pos, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    /* First match wins (or looses), ALWAYS/DEFAULT implies ALLOW */
    if (device_matches_rule(rule, device) &&
        vm_matches_rule(rule, vm))
    {
      if (rule->cmd != DENY) {
        xd_log(LOG_INFO,
            "Assignment of device [Bus=%03d, Dev=%03d, VID=%04X, PID=%04X, Serial=%s] to VM [UUID=%s], allowed by rule %d",
            device->busid,
            device->devid,
            device->vendorid,
            device->deviceid,
            device->serial,
            vm->uuid,
            rule->pos);
        if (rule_ptr != NULL)
          *rule_ptr = rule;
        return true;
      }
      else {
        xd_log(LOG_INFO,
            "Assignment of device [Bus=%03d, Dev=%03d, VID=%04X, PID=%04X, Serial=%s] to VM [UUID=%s], denied by rule %d",
            device->busid,
            device->devid,
            device->vendorid,
            device->deviceid,
            device->serial,
            vm->uuid,
            rule->pos);
        if (rule_ptr != NULL)
          *rule_ptr = rule;
        return false;
      }
    }
  }

  /* No match found, default to DENY. Return TRUE here to default to ALLOW */
  xd_log(LOG_INFO,
    "No rule qualifying assignment of device [Bus=%03d, Dev=%03d, VID=%04X, PID=%04X, Serial=%s] to VM [UUID=%s], implicitly denying",
    device->busid,
    device->devid,
    device->vendorid,
    device->deviceid,
    device->serial,
    vm->uuid);
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
  int res = 1;

  if (device == NULL) return 1;

  /* Don't auto assign ambiguous devices */
  if (device_is_ambiguous(device)) {
    xd_log(LOG_INFO,
        "Rejecting automatic assignment of ambiguous device: Bus=%d Dev=%d",
        device->busid,
        device->devid);
    return 1;
  }

  /* If there's a sticky/default rule for the device, assign it to the
   * corresponding VM (if it's running). If there's no sticky/default rule
   * for the device, consider assigning it to the focused VM */
  rule = sticky_lookup(device);
  if (rule == NULL)
    rule = default_lookup(device);
  if (rule != NULL) {
    vm = vm_lookup_by_uuid(rule->vm_uuid);
  } else {
    vm = vm_focused();
    if (vm != NULL && vm->domid > 0 && !vm_gets_devices_when_in_focus(vm))
      vm = NULL;
  }

  property_get_com_citrix_xenclient_xenmgr_vm_domid_(g_xcbus, XENMGR, UIVM_PATH, &uivm);
  if (vm != NULL &&
      vm->domid > 0 &&
      vm->domid != uivm &&
      policy_is_allowed(device, vm, &rule)) {
    device->vm = vm;
    res = usbowls_plug_device(vm->domid, device->busid, device->devid);
    if (res != 0)
      device->vm = NULL;
    xd_log(LOG_INFO,
        "Automatically assigned device [Bus=%03d, Dev=%03d, VID=%04X, PID=%04X, Serial=%s] to VM [UUID=%s, DomID=%d], according to policy rule %d",
        device->busid,
        device->devid,
        device->vendorid,
        device->deviceid,
        device->serial,
        vm->uuid,
        vm->domid,
        rule->pos);
  }

  return res;
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
  struct list_head *pos, *device_pos, *tmp;
  rule_t *rule;
  device_t *device;
  int ret = 0;
  int clean = 0;

  /* For all the ALWAYS and DEFAULT rules that match the VM,
   * assign all devices that match the rule to the VM */
  list_for_each_safe(pos, tmp, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    if ((rule->cmd == ALWAYS || rule->cmd == DEFAULT) &&
       rule->vm_uuid != NULL && /* NULL vm_uuid means dom0, means no assignment */
       !strcmp(rule->vm_uuid, vm->uuid)) {
      list_for_each(device_pos, &devices.list) {
        device = list_entry(device_pos, device_t, list);
        if (!device_matches_rule(rule, device))
          continue;
        /* The device matches the rule, let's try to assign it */
        if (device->vm != NULL) {
          if (device->vm != vm) {
            xd_log(LOG_ERR, "An always-assign device is assigned to another VM, this shouldn't happen!");
            ret = -1;
            continue;
          } else {
            /* The device is already assigned to the right VM */
            continue;
          }
        } else {
          /* Don't auto assign ambiguous devices */
          if (device_is_ambiguous(device)) {
            xd_log(LOG_INFO,
                "Skipping automatic assignment of ambiguous device: Bus=%d Dev=%d, rule %d will be removed",
                device->busid,
                device->devid,
                rule->pos);
            clean = 1;
            continue;
          }

          /* The device is not assigned, as expected, plug it to its VM */
          /* No need to check the policy, ALWAYS implies ALLOW */
          device->vm = vm;
          ret |= -usbowls_plug_device(vm->domid, device->busid, device->devid);
          xd_log(LOG_INFO,
              "Automatically assigned device [Bus=%03d, Dev=%03d, VID=%04X, PID=%04X, Serial=%s] to VM [UUID=%s, DomID=%d], according to policy rule %d",
              device->busid,
              device->devid,
              device->vendorid,
              device->deviceid,
              device->serial,
              rule->vm_uuid,
              vm->domid,
              rule->pos);
        }
      }
    }
    /* Cleanse rule because UI thinks unassigned devices are attached due to
     * sticky association */
    if (clean == 1) {
      list_del(&rule->list);
      policy_free_rule(rule);
      db_write_policy(&rules);
      clean = 0;
    }
  }

  return ret;
}

enum command
policy_parse_command_string(const char* cmd)
{
  if (cmd == NULL || cmd[0] == '\0') return DENY;

  if (strcmp(cmd, "allow") == 0) return ALLOW;
  if (strcmp(cmd, "always") == 0) return ALWAYS;
  if (strcmp(cmd, "default") == 0) return DEFAULT;
  if (strcmp(cmd, "deny") == 0) return DENY;

  return UNKNOWN;
}

char*
policy_parse_command_enum(enum command cmd)
{
  char* command = calloc(sizeof(char),8);
  switch (cmd)
  {
    case ALLOW:
      strcpy(command, "allow");
      break;
    case ALWAYS:
      strcpy(command, "always");
      break;
    case DEFAULT:
      strcpy(command, "default");
      break;
    default:
      strcpy(command, "deny");
      break;
  }
  return command;
}

static void
policy_flush_pairs(char ***list)
{
  char **s;

  if (*list == NULL)
    /* The list is empty */
    return;

  s = *list;
  while (*s != NULL) {
    free(*s);
    s++;
  }
  free(*list);
}

void
policy_free_rule(rule_t *rule)
{
  if (rule == NULL) return;
  free(rule->desc);
  free(rule->dev_serial);
  policy_flush_pairs(&rule->dev_sysattrs);
  policy_flush_pairs(&rule->dev_properties);
  free(rule->vm_uuid);
  free(rule);
}

static void
policy_flush_rules(void)
{
  struct list_head *pos, *tmp;
  rule_t *rule;

  list_for_each_safe(pos, tmp, &rules.list) {
    rule = list_entry(pos, rule_t, list);
    list_del(pos);
    policy_free_rule(rule);
  }
}

/**
 * Empty the list of rules and re-read it from the database.
 * Call this whenever the policy gets modified outside of this daemon.
 */
void
policy_reload_from_db(void)
{
  policy_flush_rules();
  db_read_policy(&rules);
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
