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
 * @file   device.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Tue Jul 21 10:45:37 2015
 *
 * @brief  Device list manipulation functions
 *
 * Functions to add/remove/lookup devices
 */


#include "project.h"

/**
 * Lookup a device in the list using its busid and devid
 *
 * @param busid The bus ID of the device
 * @param devid The ID of the device on the bus
 *
 * @return A pointer to the device if found, NULL otherwise
 */
device_t*
device_lookup(int busid, int devid)
{
  struct list_head *pos;
  device_t *device;

  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      return device;
    }
  }

  return NULL;
}

/**
 * Lookup a device in the list using its vendor ID, device ID and
 * serial. If the serial is NULL, ignore it
 *
 * @param vendorid The vendor ID of the device
 * @param deviceid The device ID of the device
 * @param serial   The serial of the device, or NULL
 *
 * @return A pointer to the first device found, NULL otherwise
 */
device_t*
device_lookup_by_attributes(int vendorid,
                            int deviceid,
                            char *serial)
{
  struct list_head *pos;
  device_t *device;

  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->vendorid == vendorid &&
        device->deviceid == deviceid &&
        (serial == NULL || !(strcmp(device->shortname, serial)))) {
      return device;
    }
  }

  return NULL;
}

/**
 * Add a new device to the global list of devices
 *
 * @param busid The device bus ID
 * @param devid The device ID on the bus
 * @param vendorid The device vendor ID
 * @param deviceid The device device ID
 * @param shortname The short description of the device (product name)
 * @param longname The long description of the device (manufacturer)
 * @param sysname The sysfs name of the device
 *
 * @return A pointer to the newly created device
 */
device_t*
device_add(int  busid, int  devid,
           int  vendorid, int  deviceid,
           char *shortname, char *longname,
           char *sysname, struct udev_device *udev)
{
  device_t *device;

  device = malloc(sizeof(device_t));

  device->busid = busid;
  device->devid = devid;
  device->vendorid = vendorid;
  device->deviceid = deviceid;
  device->shortname = shortname;
  device->longname = longname;
  device->sysname = sysname;
  device->udev = udev;
  device->vm = NULL; /* The UI isn't happy if the device is assigned to dom0 */
  device->type = 0;
  list_add(&device->list, &devices.list);

  return device;
}

/**
 * Remove a device from the global list of devices
 *
 * @param busid The device bus ID
 * @param devid The device ID on the bus
 *
 * @return 0 for success, -1 if the device wasn't found
 */
int
device_del(int  busid,
           int  devid)
{
  struct list_head *pos;
  device_t *device;

  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      break;
    }
  }
  if (device->busid == busid && device->devid == devid) {
    list_del(pos);
    free(device->shortname);
    free(device->longname);
    free(device->sysname);
    udev_device_unref(device->udev);
    free(device);
  } else {
    xd_log(LOG_ERR, "Device not found: %d-%d", busid, devid);
    return -1;
  }

  return 0;
}

/**
 * Build a string that represents the device type
 * by finding the deepest known class/subclass/protocol.
 * This uses the structure defined in classes.h, generated from
 * usb.ids.
 * The caller is responsible for freeing the returned string.
 *
 * @param class The device class
 * @param subclass The device subclass
 * @param protocol The device protocol
 *
 * @return The deepest class string found (protocol || subclass || class)
 *         or NULL if none
 */
char*
device_type(unsigned char class,
            unsigned char subclass,
            unsigned char protocol)
{
  const class_t *tmp = classes;
  int n = 0;
  int m = 0;
  int size;
  char *res;

  /* Find the class */
  while (tmp->value != NULL && tmp->id != class)
    tmp++;
  if (tmp->value == NULL)
    return NULL;

  /* Find the subclass or return the class */
  while (tmp->subs != NULL && tmp->subs[n].value != NULL &&
         tmp->subs[n].id != subclass)
    n++;
  if (tmp->subs == NULL || tmp->subs[n].value == NULL)
  {
    size = strlen(tmp->value) + 1;
    res = malloc(size);
    snprintf(res, size, "%s", tmp->value);
    return res;
  }

  /* Find the protocol or return the "class - subclass" */
  while (tmp->subs[n].prots != NULL && tmp->subs[n].prots[m].value != NULL &&
         tmp->subs[n].prots[m].id != protocol)
    m++;
  if (tmp->subs[n].prots == NULL || tmp->subs[n].prots[m].value == NULL)
  {
    size = strlen(tmp->value) + strlen(" - ") + strlen(tmp->subs[n].value) + 1;
    res = malloc(size);
    snprintf(res, size, "%s - %s", tmp->value, tmp->subs[n].value);
    return res;
  }

  /* Everything was found, returning the "class - protocol" */
  size = strlen(tmp->value) + strlen(" - ") + strlen(tmp->subs[n].prots[m].value) + 1;
  res = malloc(size);
  snprintf(res, size, "%s - %s", tmp->value, tmp->subs[n].prots[m].value);

  return res;
}

/**
 * Iterate through all the devices attached to the VM and unplug them
 *
 * @param domid The domid of the VM
 *
 * @return 0 on complete success
 */
int
device_unplug_all_from_vm(int domid)
{
  struct list_head *pos;
  device_t *device;
  int res = 0;

  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->vm != NULL && device->vm->domid == domid) {
      res |= usbowls_unplug_device(domid, device->busid, device->devid);
      device->vm = NULL;
    }
  }

  return res;
}
