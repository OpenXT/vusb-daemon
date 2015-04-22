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

#include "project.h"

int
check_sysname(char *s)
{
  while (*s != '\0') {
    if (*s == ':')
      return -1;
    s++;
  }

  return 0;
}

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

  /* Find the subclass */
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

  /* Find the protocol */
  while (tmp->subs[n].prots != NULL && tmp->subs[n].prots[m].value != NULL &&
	 tmp->subs[n].prots[m].id != protocol)
    m++;
  if (tmp->subs[n].prots == NULL || tmp->subs[n].prots[m].value == NULL)
    {
      size = strlen(tmp->subs[n].value) + 1;
      res = malloc(size);
      snprintf(res, size, "%s", tmp->subs[n].value);
      return res;
    }

  /* Everything was found */
  size = strlen(tmp->subs[n].prots[m].value) + 1;
  res = malloc(size);
  snprintf(res, size, "%s", tmp->subs[n].prots[m].value);

  return res;
}

int
add_device(int  busid,
	   int  devid,
	   char *shortname,
	   char *longname)
{
  device_t *device;

  device = malloc(sizeof(device_t));

  device->busid = busid;
  device->devid = devid;
  device->shortname = shortname;
  device->longname = longname;
  device->vm = NULL;
  list_add(&device->list, &devices.list);

  return 0;
}

int
fill_devices(void)
{
  struct udev_enumerate *enumerate;
  struct udev *udev;
  struct udev_list_entry *udev_device_list, *udev_device_entry;
  struct udev_device *udev_device;
  uint16_t vendor = 0;
  uint16_t product = 0;

  udev = udev_new();
  if (!udev) {
    xd_log(LOG_ERR, "Can't do udev");
    return -1;
  }
  enumerate = udev_enumerate_new(udev);
  udev_enumerate_add_match_subsystem(enumerate, "usb");
  /* Sysname must start with a digit */
  udev_enumerate_add_match_sysname(enumerate, "[0-9]*");
  udev_enumerate_scan_devices(enumerate);
  udev_device_list = udev_enumerate_get_list_entry(enumerate);
  udev_list_entry_foreach(udev_device_entry, udev_device_list) {
    const char *path;
    const char *value;
    int busnum;
    int devnum;
    char *vendor;
    char *model;
    char *type = NULL;
    unsigned char class;
    unsigned char subclass;
    unsigned char protocol;
    int size;

    path = udev_list_entry_get_name(udev_device_entry);
    udev_device = udev_device_new_from_syspath(udev, path);

    value = udev_device_get_sysname(udev_device);
    if (value != NULL && check_sysname(value) != 0)
      continue;

    value = udev_device_get_sysattr_value(udev_device, "busnum");
    if (value == NULL)
      continue;
    else
      busnum = strtol(value, NULL, 10);
    value = udev_device_get_sysattr_value(udev_device, "devnum");
    if (value == NULL)
      continue;
    else
      devnum = strtol(value, NULL, 10);
    value = udev_device_get_sysattr_value(udev_device, "bDeviceClass");
    if (value == NULL)
      continue;
    else
      class = strtol(value, NULL, 16);
    value = udev_device_get_sysattr_value(udev_device, "bDeviceSubClass");
    if (value == NULL)
      continue;
    else
      subclass = strtol(value, NULL, 16);
    value = udev_device_get_sysattr_value(udev_device, "bDeviceProtocol");
    if (value == NULL)
      continue;
    else
      protocol = strtol(value, NULL, 16);

    /* This is a hub, we don't do hubs. */
    if (class == 0x09)
      continue;

    if (class != 0)
      type = device_type(class, subclass, protocol);

    value = udev_device_get_property_value(udev_device, "ID_VENDOR_FROM_DATABASE");
    if (value != NULL) {
      vendor = malloc(strlen(value) + 1);
      strcpy(vendor, value);
    }
    value = udev_device_get_property_value(udev_device, "ID_MODEL_FROM_DATABASE");
    if (value == NULL)
      value = udev_device_get_sysattr_value(udev_device, "product");
    if (value != NULL) {
      if (type != NULL) {
	size = strlen(type) + 3 + strlen(value) + 1;
	model = malloc(size);
	snprintf(model, size, "%s - %s", value, type);
      } else {
	size = strlen(value) + 1;
	model = malloc(size);
	snprintf(model, size, "%s", value);
      }
    } else {
      if (type != NULL) {
	size = strlen(type) + 1;
	model = malloc(size);
	snprintf(model, size, "%s", type);
      } else {
	size = strlen("unknown" + 1);
	model = malloc(size);
	snprintf(model, size, "unknown");
      }
    }
    add_device(busnum, devnum, model, vendor);
  }
  udev_enumerate_unref(enumerate);
  udev_unref(udev);
}

int
main() {
  int ret;
  vm_t *vm;
  struct timeval tv;
  fd_set readfds;
  fd_set writefds;
  fd_set exceptfds;
  int nfds;

  INIT_LIST_HEAD(&vms.list);
  INIT_LIST_HEAD(&devices.list);

  vm = malloc(sizeof(vm_t));

  vm->domid = DOM0_DOMID;
  vm->uuid = DOM0_UUID;
  list_add(&vm->list, &vms.list);

  fill_devices();

  ret = usbowls_xenstore_init();
  if (ret != 0)
    return ret;

  /* What is that? */
  xenstore_init();

  rpc_init();

  while (1) {
    /* Check dbus */
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    nfds = xcdbus_pre_select(g_xcbus, 0, &readfds, &writefds, &exceptfds);
    select(nfds, &readfds, &writefds, &exceptfds, &tv);
    xcdbus_post_select(g_xcbus, 0, &readfds, &writefds, &exceptfds);

    /* Check udev */
  }

  /* In the future, the while loop may break on critical error */
  ret = usbowls_xenstore_deinit();

  return ret;
}
