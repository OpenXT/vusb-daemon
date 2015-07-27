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

#define STICKY_FILE_PATH "/config/etc/USB_always.conf"

/**
 * @brief Sticky rule
 *
 * This represents a "sticky rule", which tells which specific device
 * always gets assigned to which specific VM.
 */
typedef struct {
  struct list_head list;        /**< The kernel-list-like list item */
  int vendorid;                 /**< The device vendor ID */
  int deviceid;                 /**< The device device ID */
  char *serial;                 /**< The device serial (shortname) */
  char *uuid;                   /**< The uuid of the VM  */
} sticky_t;

/**
 * If this stays true, it means devices are automatically assigned to
 * the VM that currently has the focus (unless there's a sticky rule
 * for assigning it to another running VM)
 */
static bool auto_assign_to_focused_vm = true;

/**
 * The global list of sticky rules, that's only used by policy.c
 */
sticky_t stickys;

static int
policy_dump_stickys_to_file(void)
{
  FILE *file;
  char line[1024];
  int ret;
  struct list_head *pos;

  file = fopen(STICKY_FILE_PATH, "w");
  if (file == NULL)
  {
    xd_log(LOG_WARN, "No USB sticky loaded as the file couldn't be opened");
    return -1;
  }
  list_for_each(pos, &stickys.list)
  {
    sticky_t *sticky;

    sticky = list_entry(pos, sticky_t, list);
    snprintf(line, 1024, "%X:%X:\"%s\"=\"%s\"\n",
             sticky->vendorid, sticky->deviceid, sticky->serial, sticky->uuid);
    fputs(line, file);
  }
  fclose(file);
}

static void
sticky_add_noalloc(int vendorid,
                   int deviceid,
                   char *serial,
                   char *uuid)
{
  sticky_t *sticky;

  sticky = malloc(sizeof(sticky_t));
  sticky->vendorid = vendorid;
  sticky->deviceid = deviceid;
  sticky->serial = serial;
  sticky->uuid = uuid;
  list_add(&sticky->list, &stickys.list);
}

static void
sticky_add(int vendorid,
           int deviceid,
           const char *serial,
           const char *uuid)
{
  char *newserial, *newuuid;

  newserial = malloc(strlen(serial) + 1);
  strcpy(newserial, serial);
  newuuid = malloc(strlen(uuid) + 1);
  strcpy(newuuid, uuid);
  sticky_add_noalloc(vendorid, deviceid, newserial, newuuid);
}

static sticky_t*
sticky_lookup(int vendorid,
              int deviceid,
              const char *serial)
{
  struct list_head *pos;
  sticky_t *sticky;

  list_for_each(pos, &stickys.list) {
    sticky = list_entry(pos, sticky_t, list);
    /* Check for a match. Ignore any trailing info in the serial. */
    if (sticky->vendorid == vendorid &&
        sticky->deviceid == deviceid &&
        !strncmp(sticky->serial, serial, strlen(sticky->serial))) {
      return sticky;
    }
  }

  return NULL;
}

static int
sticky_del(int vendorid,
           int deviceid,
           const char *serial)
{
  sticky_t *sticky;

  sticky = sticky_lookup(vendorid, deviceid, serial);
  if (sticky == NULL)
    return -1;
  list_del(&sticky->list);
  free(sticky->serial);
  free(sticky->uuid);
  free(sticky);

  return 0;
}

static int
policy_read_stickys_from_file(void)
{
  FILE *file;
  char line[1024];
  int ret;

  file = fopen(STICKY_FILE_PATH, "r");
  if (file == NULL)
  {
    xd_log(LOG_WARN, "No USB sticky loaded as the file couldn't be opened");
    return 0;
  }
  while (fgets(line, 1024, file) != NULL)
  {
    char *begin = line;
    char *end;
    int size;
    int vendorid, deviceid;
    char *serial, *uuid;

    /* Default to failure if we break */
    ret = -2;

    /* Read the vendorid and make sure it's followed by ':' */
    vendorid = strtol(begin, &end, 16);
    if (end == NULL || *end != ':')
      break;
    begin = end + 1;

    /* Read the deviceid and make sure it's followed by ':' and '"' */
    deviceid = strtol(begin, &end, 16);
    if (end == NULL || *end != ':' || *(end + 1) != '"')
      break;
    begin = end + 2;

    /* Read the serial and make sure it's followed by '"', '=', and '"' */
    end = strchr(begin, '"');
    if (end == NULL)
      break;
    size = end - begin;
    serial = malloc(size + 1);
    strncpy(serial, begin, size);
    serial[size] = '\0';
    if (end == NULL || *end != '"' || *(end + 1) != '=' || *(end + 2) != '"')
      break;
    begin = end + 3;

    /* Read the uuid and make sure it's UUID_LENGTH, and followed by '"'.
       The end of the line will be discarded */
    end = strchr(begin, '"');
    if (end == NULL)
      break;
    size = end - begin;
    if (size != UUID_LENGTH - 1)
      break;
    uuid = malloc(size + 1);
    strncpy(uuid, begin, size);
    uuid[size] = '\0';
    if (end == NULL || *end != '"')
      break;

    /* All set. Create the rule item and set ret to success (0) */
    sticky_add_noalloc(vendorid, deviceid, serial, uuid);
    ret = 0;
  }

  if (ret == -2)
    xd_log(LOG_ERR, "Error while reading the USB sticky file");
  fclose(file);

  return ret;
}

/**
 * Create a new sticky rule using a device and its currently assigned
 * VM, then dump the rules to the persistant config file.
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

  makeBusDevPair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL || device->vm == NULL)
    return -1;
  sticky_add(device->vendorid, device->deviceid, device->shortname, device->vm->uuid);
  policy_dump_stickys_to_file();

  return 0;
}

/**
 * Delete a sticky rule matching a device. On success, dump the rules
 * to the persistant config file
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
  int ret;

  makeBusDevPair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL)
    return -1;
  ret = sticky_del(device->vendorid, device->deviceid, device->shortname);
  if (ret == 0)
    policy_dump_stickys_to_file();

  return ret;
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
  sticky_t *sticky;
  int ret;

  makeBusDevPair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL)
    return NULL;
  sticky = sticky_lookup(device->vendorid, device->deviceid, device->shortname);
  if (sticky != NULL)
    return sticky->uuid;
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
  sticky_t *sticky;
  vm_t *vm = NULL;
  int uivm;

  /* If there's a sticky rule for the device, assign the the
   * corresponding VM (if it's running). If there's no sticky rule
   * for the device, consider assigning it to the focused VM */
  sticky = sticky_lookup(device->vendorid, device->deviceid, device->shortname);
  if (sticky != NULL) {
    vm = vm_lookup_by_uuid(sticky->uuid);
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
  sticky_t *sticky;
  device_t *device;
  int ret = 0;

  list_for_each(pos, &stickys.list) {
    sticky = list_entry(pos, sticky_t, list);
    if (!strcmp(sticky->uuid, vm->uuid)) {
      device = device_lookup_by_attributes(sticky->vendorid,
                                           sticky->deviceid,
                                           sticky->serial);
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
 * an eventual persistant config file.
 */
int
policy_init(void)
{
  INIT_LIST_HEAD(&stickys.list);

  return policy_read_stickys_from_file();
}
