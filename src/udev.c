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

static struct udev_monitor *udev_mon;

int
udev_init(void)
{
  struct udev *udev;
  int fd;

  /* Initialise udev monitor */
  udev = udev_new();
  if(udev == NULL)
    {
      printf("Can't create udev monitor");
      return -1;
    }

  udev_mon = udev_monitor_new_from_netlink(udev, "udev");
  udev_monitor_filter_add_match_subsystem_devtype(udev_mon, "usb", "usb_device");
  udev_monitor_enable_receiving(udev_mon);
  fd = udev_monitor_get_fd(udev_mon);

  return fd;
}

/* Ignore device configurations and interfaces */
static int
check_sysname(const char *s)
{
  while (*s != '\0') {
    if (*s == ':')
      return -1;
    s++;
  }

  return 0;
}

int
udev_maybe_add_device(struct udev_device *dev, int auto_assign)
{
  const char *value;
  int busnum, devnum;
  int vendorid, deviceid;
  char *vendor = NULL;
  char *model;
  char *type = NULL;
  char *sysname = NULL;
  unsigned char class;
  unsigned char subclass;
  unsigned char protocol;
  int size;
  device_t *device;

  /* Make sure the device is useful for us */
  value = udev_device_get_sysname(dev);
  if (value != NULL && check_sysname(value) != 0)
    return -1;

  /* Check main device attributes.
     Skip any device that doesn't have them (shouldn't happen) */
  value = udev_device_get_sysattr_value(dev, "busnum");
  if (value == NULL)
    return -1;
  else
    busnum = strtol(value, NULL, 10);
  value = udev_device_get_sysattr_value(dev, "devnum");
  if (value == NULL)
    return -1;
  else
    devnum = strtol(value, NULL, 10);
  value = udev_device_get_sysattr_value(dev, "idVendor");
  if (value == NULL)
    return -1;
  else
    vendorid = strtol(value, NULL, 10);
  value = udev_device_get_sysattr_value(dev, "idProduct");
  if (value == NULL)
    return -1;
  else
    deviceid = strtol(value, NULL, 10);
  value = udev_device_get_sysattr_value(dev, "bDeviceClass");
  if (value == NULL)
    return -1;
  else
    class = strtol(value, NULL, 16);
  value = udev_device_get_sysattr_value(dev, "bDeviceSubClass");
  if (value == NULL)
    return -1;
  else
    subclass = strtol(value, NULL, 16);
  value = udev_device_get_sysattr_value(dev, "bDeviceProtocol");
  if (value == NULL)
    return -1;
  else
    protocol = strtol(value, NULL, 16);
  value = udev_device_get_sysname(dev);
  if (value == NULL)
    return -1;
  else {
    size = strlen(value) + 1;
    sysname = malloc(size);
    strncpy(sysname, value, size);
  }

  /* This is a hub, we don't do hubs. */
  if (class == 0x09)
    return -1;

  /* The devices passes all the tests, we want it in the list */

  /* Get the type string for the device. 0 is not a "real" class */
  if (class != 0)
    type = device_type(class, subclass, protocol);

  /* Using udev to look up the device vendor in usb.ids.
     If no vendor is found in the database, ask the device itself.
     If no vendor is found at all, the device longname will be NULL. */
  value = udev_device_get_property_value(dev, "ID_VENDOR_FROM_DATABASE");
  if (value == NULL)
    value = udev_device_get_property_value(dev, "ID_VENDOR");
  if (value != NULL) {
    vendor = malloc(strlen(value) + 1);
    strcpy(vendor, value);
  }

  /* Using udev to look up the device model in usb.ids.
     If no model is found in the database, ask the device itself.
     Use model and type to build the shortname or default to "unknown" */
  value = udev_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE");
  if (value == NULL)
    value = udev_device_get_property_value(dev, "ID_MODEL");
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

  /* Finally add the device */
  device = device_add(busnum, devnum, vendorid, deviceid, model, vendor, sysname);

  if (auto_assign > 0)
    policy_auto_assign(device);

  return 0;
}

static void
udev_node_to_ids(const char *node, int *busid, int *devid)
{
  char *tmp;

  /* USB devnodes look like "/dev/bus/usb/XXX/YYY",
   XXX being the busid and YYY being the devid.
   If other formats are ever encountered,
     we may consider storing the devnode in device_t */

  /* Instead of skipping 13 characters ("/dev/bus/usb/"),
       just go to the first digit. */
  while (*node != '\0' && (*node > '9' || *node < '0'))
    node++;

  /* strtol will stop at the next "/", and set tmp to its position */
  *busid = strtol(node, &tmp, 10);

  /* Instead of skipping 1 character ("/"), just go to the next digit. */
  while (*tmp != '\0' && (*tmp < '0' || *tmp > '9' ))
    tmp++;

  *devid = strtol(tmp, NULL, 10);
}

int
udev_del_device(struct udev_device *dev)
{
  const char *node;
  const char *value;
  int busnum;
  int devnum;

  node = udev_device_get_devnode(dev);
  udev_node_to_ids(node, &busnum, &devnum);

  device_del(busnum, devnum);

  return 0;
}

int
udev_bind_device_to_dom0(struct udev_device *dev)
{
  const char *name;

  name = udev_device_get_devnode(dev);

  return device_bind_to_dom0_by_sysname(name);
}

/* Enumerate all the udev USB devices that we care about,
   build nice model and vendor strings and add them to the list */
int
udev_fill_devices(void)
{
  struct udev_enumerate *enumerate;
  struct udev *udev;
  struct udev_list_entry *udev_device_list, *udev_device_entry;
  struct udev_device *udev_device;
  const char *path;
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
      path = udev_list_entry_get_name(udev_device_entry);
      udev_device = udev_device_new_from_syspath(udev, path);
      udev_maybe_add_device(udev_device, 0);
      udev_device_unref(udev_device);
  }

  /* Cleanup */
  udev_enumerate_unref(enumerate);
  udev_unref(udev);
}

void
udev_event(void)
{
  struct udev_device *dev;
  const char *action;

  dev = udev_monitor_receive_device(udev_mon);
  if (dev) {
    action = udev_device_get_action(dev);
    printf("Got Device\n");
    printf("   Node: %s\n", udev_device_get_devnode(dev));
    printf("   Subsystem: %s\n", udev_device_get_subsystem(dev));
    printf("   Sysname: %s\n", udev_device_get_sysname(dev));
    printf("   Devtype: %s\n", udev_device_get_devtype(dev));
    printf("   Action: %s\n", action);
    if (!strcmp(action, "add")) {
      printf("ADDING IT\n");
      udev_maybe_add_device(dev, 1);
    }
    if (!strcmp(action, "remove")) {
      printf("REMOVING IT\n");
      udev_del_device(dev);
    }
    udev_device_unref(dev);
  }
  else {
    printf("No Device from receive_device(). An error occured.\n");
  }
}
