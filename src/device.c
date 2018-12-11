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
        (serial == NULL || device->serial == NULL || !(strcmp(device->serial, serial)))) {
      return device;
    }
  }

  return NULL;
}

/**
 * Check managed devices for ambiguous matches
 *
 * @param device The device to check for ambiguity
 *
 * @return 0 if not ambiguous, 1 if ambiguous or error
 */
int
device_is_ambiguous(device_t *device)
{
  struct list_head *pos;
  device_t *dev;

  if (device == NULL) return 1;

  list_for_each(pos, &devices.list){
    dev = list_entry(pos, device_t, list);
    if (dev == NULL) continue;

    /* Skip if we are at the given device */
    if (dev->busid == device->busid && dev->devid == device->devid) continue;

    /* Match vendor and product(device) IDs */
    if (dev->vendorid == device->vendorid && dev->deviceid == device->deviceid){
      /* If either device had an unpopulated serial, treat as ambiguous */
      if (dev->serial == NULL || device->serial == NULL) return 1;

      /* 0-length or empty string as serial can still result in ambiguity */
      if (strlen(dev->serial) == 0 || strlen(device->serial) == 0) return 1;

      /* Compare serial numbers. Shouldn't match, but has been seen before */
      if (strncmp(dev->serial, device->serial, 256) == 0) return 1;
    }
  }

  return 0;
}

/**
 * Add a new device to the global list of devices
 *
 * @param busid The device bus ID
 * @param devid The device ID on the bus
 * @param vendorid The device vendor ID
 * @param deviceid The device device ID
 * @param serial The device serial number (may not be populated on some devices)
 * @param shortname The short description of the device (product name)
 * @param longname The long description of the device (manufacturer)
 * @param sysname The sysfs name of the device
 *
 * @return A pointer to the newly created device
 */
device_t*
device_add(int  busid, int  devid,
           int  vendorid, int  deviceid,
           int  type,
           char *serial,
           char *shortname, char *longname,
           char *sysname, struct udev_device *udev)
{
  struct list_head *pos;
  device_t *device;

  /* Fail if we already have the device */
  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      return NULL;
    }
  }

  device = malloc(sizeof(device_t));

  device->busid = busid;
  device->devid = devid;
  device->vendorid = vendorid;
  device->deviceid = deviceid;
  device->serial = serial;
  device->shortname = shortname;
  device->longname = longname;
  device->sysname = sysname;
  device->udev = udev;
  device->vm = NULL; /* The UI isn't happy if the device is assigned to dom0 */
  device->type = type;
  list_add(&device->list, &devices.list);

  return device;
}

void device_free(device_t *device)
{
  free(device->shortname);
  free(device->longname);
  free(device->sysname);
  free(device->serial);
  /* udev_device_unref is okay when udev is NULL */
  udev_device_unref(device->udev);
  free(device);
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
  device_t *device = NULL;

  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      break;
    }
  }
  if (device != NULL && device->busid == busid && device->devid == devid) {
    list_del(pos);
    device_free(device);
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
      xd_log(LOG_INFO,
          "Device [Bus=%03d, Dev=%03d, VID=%04X, PID=%04X, Serial=%s] unplugged from VM [UUID=%s, DomID=%d]",
          device->busid,
          device->devid,
          device->vendorid,
          device->deviceid,
          device->serial,
          device->vm->uuid,
          domid);
      device->vm = NULL;
    }
  }

  return res;
}

/**
 * @brief Generate a device ID
 *
 * Generate a single ID from the bus and device IDs
 * @param bus_num Device bus
 * @param dev_num Device ID on the bus
 */
int device_make_id(int bus_num, int dev_num)
{
  return ((bus_num - 1) << 7) + (dev_num - 1);
}

/**
 * @brief Get the bus and device IDs of a device
 *
 * Extract bus and device IDs from a single device ID
 * @param devid   The single ID
 * @param bus_num Resulting device bus
 * @param dev_num Resulting Device ID
 */
void device_make_bus_dev_pair(int devid, int *bus_num, int *dev_num)
{
  *bus_num = (devid >> 7) + 1;
  *dev_num = (devid & 0x7F) + 1;
}
