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
 * @file   udev.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Thu Jul 30 13:20:45 2015
 *
 * @brief  Udev interaction
 *
 * Functions that handle udev events and other udev requests
 */

#include "project.h"

/**
 * The global udev monitor handler. Only used in udev.c
 */
static struct udev_monitor *udev_mon;

/**
 * Initialize the udev bits.
 *
 * @return 0 on success, -1 if udev couldn't be initialized
 */
int
udev_init(void)
{
  int fd;

  /* Initialise udev monitor */
  udev_handle = udev_new();
  if(udev_handle == NULL)
  {
    printf("Can't create udev handle");
    return -1;
  }

  udev_mon = udev_monitor_new_from_netlink(udev_handle, "udev");
  udev_monitor_filter_add_match_subsystem_devtype(udev_mon, "usb", "usb_device");
  udev_monitor_enable_receiving(udev_mon);
  fd = udev_monitor_get_fd(udev_mon);

  return fd;
}

static void
udev_find_more_about_input(struct udev_device *udev_device,  device_t *device)
{
  const char *value;

  /* First, check if the id_input module considered the device, to
   * avoid wasting time */
  value = udev_device_get_property_value(udev_device, "ID_INPUT");
  if (value == NULL || *value == '0')
    return;

  /* The udev module id_input provides: */
  /* ID_INPUT_ACCELEROMETER */
  /* ID_INPUT_JOYSTICK      == GAME_CONTROLLER */
  /* ID_INPUT_KEY */
  /* ID_INPUT_KEYBOARD      == KEYBOARD */
  /* ID_INPUT_MOUSE         == MOUSE */
  /* ID_INPUT_TABLET */
  /* ID_INPUT_TOUCHPAD      == MOUSE */
  /* ID_INPUT_TOUCHSCREEN */
  value = udev_device_get_property_value(udev_device, "ID_INPUT_KEYBOARD");
  if (value != NULL && *value != '0')
    device->type |= KEYBOARD;
  value = udev_device_get_property_value(udev_device, "ID_INPUT_MOUSE");
  if (value != NULL && *value != '0')
    device->type |= MOUSE;
  value = udev_device_get_property_value(udev_device, "ID_INPUT_TOUCHPAD");
  if (value != NULL && *value != '0')
    device->type |= MOUSE;
  value = udev_device_get_property_value(udev_device, "ID_INPUT_JOYSTICK");
  if (value != NULL && *value != '0')
    device->type |= GAME_CONTROLLER;
}

static void
class_to_device(const char *class, device_t *device)
{
  int c;

  if (class != NULL)
  {
    c = strtol(class, NULL, 16);
    if (c == 0x08)
      device->type |= MASS_STORAGE;
  }
}

static void
udev_find_more_about_class(struct udev_device *udev_device,  device_t *device)
{
  const char *value;
  int class;

  value = udev_device_get_sysattr_value(udev_device, "bDeviceClass");
  class_to_device(value, device);
  value = udev_device_get_sysattr_value(udev_device, "bInterfaceClass");
  class_to_device(value, device);
}

/**
 * Look at all the childs of a given device to figure out more about
 * what it does
 */
static void
udev_find_more(struct udev_device *dev, device_t *device)
{
  struct udev_enumerate *enumerate;
  struct udev_list_entry *udev_device_list, *udev_device_entry;
  struct udev_device *udev_device;
  const char *path;

  enumerate = udev_enumerate_new(udev_handle);
  udev_enumerate_add_match_parent(enumerate, dev);
  udev_enumerate_scan_devices(enumerate);
  udev_device_list = udev_enumerate_get_list_entry(enumerate);
  udev_list_entry_foreach(udev_device_entry, udev_device_list) {
    path = udev_list_entry_get_name(udev_device_entry);
    udev_device = udev_device_new_from_syspath(udev_handle, path);
    udev_find_more_about_input(udev_device, device);
    udev_find_more_about_class(udev_device, device);
    udev_device_unref(udev_device);
  }

  /* Cleanup */
  udev_enumerate_unref(enumerate);
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

/* Ignore product strings that are actually just a hex/dec number */
static int
check_product(const char *s)
{
  int len;

  len = strlen(s);
  /* Skip any "0x" at the beggining */
  if (len >= 3 && *s == '0' && *(s + 1) == 'x')
    s += 2;

  if (len > 4)
    return 0;

  while (*s != '\0') {
    if ((*s < '0' || *s > '9') &&
        (*s < 'a' || *s > 'f') &&
        (*s < 'A' || *s > 'F'))
      /* This is not a hex/dec digit, all good */
      return 0;
    s++;
  }

  return -1;
}

/* Let's do our best to make sure device are properly created */
static void
udev_settle(void)
{
  struct udev_queue *queue;
  unsigned int i;

  queue = udev_queue_new(udev_handle);
  if (!queue) {
    xd_log(LOG_WARN, "udev_queue_new failed");
    /* We failed to get a queue, let's just sleep 0.1 seconds,
       it's usually enough the get udev settled... */
    usleep(100000);
    return;
  }

  for (i = 0; i < 10; ++i) {
    if (udev_queue_get_queue_is_empty(queue)) {
      break;
    }
    xd_log(LOG_INFO, "udev queue is not empty, retrying for %f seconds...", 0.5 - i * 0.05);
    /* Sleep for 0.05 seconds 10 times before giving up */
    usleep(50000);
  }

  udev_queue_unref(queue);
}


static device_t*
udev_maybe_add_device(struct udev_device *dev, int auto_assign)
{
  const char *value;
  int busnum, devnum;
  int vendorid, deviceid;
  char *vendor = NULL;
  char *model;
  char *sysname = NULL;
  unsigned char class;
  unsigned char subclass;
  unsigned char protocol;
  int size;
  device_t *device;

  /* Give udev some time to finish create the device and its children.
     We could probably use udev_device_get_is_initialized() if it worked... */
  udev_settle();

  /* Make sure the device is useful for us */
  value = udev_device_get_sysname(dev);
  if (value != NULL && check_sysname(value) != 0)
    return NULL;

  /* Check main device attributes.
     Skip any device that doesn't have them (shouldn't happen) */
  value = udev_device_get_sysattr_value(dev, "busnum");
  if (value == NULL)
    return NULL;
  else
    busnum = strtol(value, NULL, 10);
  value = udev_device_get_sysattr_value(dev, "devnum");
  if (value == NULL)
    return NULL;
  else
    devnum = strtol(value, NULL, 10);
  value = udev_device_get_sysattr_value(dev, "idVendor");
  if (value == NULL)
    return NULL;
  else
    vendorid = strtol(value, NULL, 16);
  value = udev_device_get_sysattr_value(dev, "idProduct");
  if (value == NULL)
    return NULL;
  else
    deviceid = strtol(value, NULL, 16);
  value = udev_device_get_sysattr_value(dev, "bDeviceClass");
  if (value == NULL)
    return NULL;
  else
    class = strtol(value, NULL, 16);
  value = udev_device_get_sysattr_value(dev, "bDeviceSubClass");
  if (value == NULL)
    return NULL;
  else
    subclass = strtol(value, NULL, 16);
  value = udev_device_get_sysattr_value(dev, "bDeviceProtocol");
  if (value == NULL)
    return NULL;
  else
    protocol = strtol(value, NULL, 16);
  value = udev_device_get_sysname(dev);
  if (value == NULL)
    return NULL;
  else {
    size = strlen(value) + 1;
    sysname = malloc(size);
    strncpy(sysname, value, size);
  }

  /* This is a hub, we don't do hubs. */
  if (class == 0x09)
    return NULL;

  /* The device passes all the tests, we want it in the list */

  /* Read the device manufacturer */
  value = udev_device_get_sysattr_value(dev, "manufacturer");
  if (value == NULL)
    /* If it doesn't have a vendor, use udev to look it up in usb.ids. */
    value = udev_device_get_property_value(dev, "ID_VENDOR_FROM_DATABASE");
  if (value == NULL) {
    /* usb.ids doesn't know about it either... Default to "Unknown" */
    size = strlen("Unknown") + 1;
    vendor = malloc(size);
    snprintf(vendor, size, "Unknown");
  } else {
    /* Vendor was found in usb.ids */
    size = strlen(value) + 1;
    vendor = malloc(size);
    snprintf(vendor, size, "%s", value);
  }

  /* Read the device name. Hopefuly it's not garbage... */
  /* As a basic filter, discard names that are 4 digits long or less. */
  value = udev_device_get_sysattr_value(dev, "product");
  if (value == NULL || check_product(value) != 0)
    /* It doesn't have a name. Use udev to look it up in usb.ids. */
    value = udev_device_get_property_value(dev, "ID_MODEL_FROM_DATABASE");
  if (value == NULL) {
    /* usb.ids doesn't know about it either...
       default to "<vendor> device (<type>)" */
    char *type;

    /* Get the type string for the device. */
    type = device_type(class, subclass, protocol);
    if (type != NULL) {
      /* There's a type, let's do "<vendor> device (<type>)" */
      size = strlen(vendor) + strlen(" device ()") + strlen(type) + 1;
      model = malloc(size);
      snprintf(model, size, "%s device (%s)", vendor, type);
      free(type);
    } else {
      /* There's no type, let's just do "<vendor> device (<vendorid>:<deviceid>)" */
      size = strlen(vendor) + strlen(" device (XXXX:XXXX)") + 1;
      model = malloc(size);
      snprintf(model, size, "%s device (%04x:%04x)", vendor, vendorid, deviceid);
    }
  } else {
    /* Model was found in usb.ids */
    model = malloc(strlen(value) + 1);
    strcpy(model, value);
  }

  /* Finally add the device */
  device = device_add(busnum, devnum,
                      vendorid, deviceid,
                      model, vendor,
                      sysname, dev);

  /* Find out more about the device by looking at its children */
  udev_find_more(dev, device);

  if (auto_assign > 0)
    policy_auto_assign_new_device(device);

  return device;
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

/**
 * Cleanup xenstore and delete a device after a udev removal event.
 *
 * @param dev Udev handle of the device
 *
 * @return 0 on success, 1 if nothing happened, -1 on failure
 */
int
udev_del_device(struct udev_device *dev)
{
  const char *node;
  const char *value;
  int busnum;
  int devnum;
  usbinfo_t ui;
  dominfo_t di;
  device_t *device;
  int ret;

  /* Find the bus and device IDs */
  node = udev_device_get_devnode(dev);
  if (node == NULL)
    return -1;
  udev_node_to_ids(node, &busnum, &devnum);

  /* Cleanup xenstore if the device was assigned to a VM */
  device = device_lookup(busnum, devnum);
  if (device == NULL) {
    /* This happens if udev_maybe_add_device failed earlier, like on
     * quick plug-unplug */
    return 1;
  }
  if (device->vm != NULL) {
    usbowls_build_usbinfo(busnum, devnum, device->vendorid, device->deviceid, &ui);
    xenstore_get_dominfo(device->vm->domid, &di);
    xenstore_destroy_usb(&di, &ui);
  }

  /* Delete the device from the global list */
  ret = device_del(busnum, devnum);

  return ret;
}

/**
 * Enumerate all the udev USB devices that we care about,
 * build nice model and vendor strings and add them to the list
 */
void
udev_fill_devices(void)
{
  struct udev_enumerate *enumerate;
  struct udev_list_entry *udev_device_list, *udev_device_entry;
  struct udev_device *udev_device;
  const char *path;
  uint16_t vendor = 0;
  uint16_t product = 0;

  enumerate = udev_enumerate_new(udev_handle);
  udev_enumerate_add_match_subsystem(enumerate, "usb");
  /* Sysname must start with a digit */
  udev_enumerate_add_match_sysname(enumerate, "[0-9]*");
  udev_enumerate_scan_devices(enumerate);
  udev_device_list = udev_enumerate_get_list_entry(enumerate);
  udev_list_entry_foreach(udev_device_entry, udev_device_list) {
    path = udev_list_entry_get_name(udev_device_entry);
    udev_device = udev_device_new_from_syspath(udev_handle, path);
    udev_maybe_add_device(udev_device, 0);
    /* We keep a reference to the udev device, mainly for advanced rule-matching */
    /* udev_device_unref(udev_device); */
  }

  /* Cleanup */
  udev_enumerate_unref(enumerate);
}

/**
 * Udev monitor "callback". This function will add/delete devices
 * according to a udev event. It should be called every time the udev
 * monitor "wakes up".
 */
void
udev_event(void)
{
  struct udev_device *dev;
  const char *action;
  device_t *device;

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
      device = udev_maybe_add_device(dev, 1);
      if (device != NULL) {
        printf("   Mouse: %d\n", !!(device->type & MOUSE));
        printf("   Keyboard: %d\n", !!(device->type & KEYBOARD));
        printf("   Joystick: %d\n", !!(device->type & GAME_CONTROLLER));
        printf("   MassStorage: %d\n", !!(device->type & MASS_STORAGE));
        printf("ADDED\n");
      } else {
        /* This seems to happen when a device is quickly plugged and
         * unplugged. */
        printf("NOT ADDED\n");
      }
    }
    if (!strcmp(action, "remove")) {
      if (udev_del_device(dev) == 0)
        printf("REMOVED\n");
      else
        printf("NOT REMOVED\n");
    }
    /* We keep a reference to the udev device, mainly for advanced rule-matching */
    /* udev_device_unref(dev); */
  }
  else {
    printf("No Device from receive_device(). An error occured.\n");
  }
}
