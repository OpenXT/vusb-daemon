/*
 * Copyright (c) 2014 Citrix Systems, Inc.
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
 * @file   usbowls.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Tue Jul 21 13:54:18 2015
 *
 * @brief  Function to assign/unassign devices to VMs
 *
 * All the code used to trigger the actual device passthrough events
 * lives here. Functions in this file talk to usbback and xenstore to
 * make stuff happen.
 */

#include "project.h"

#define VUSB_ADD_DEV            "/sys/bus/usb/drivers/vusb/new_id"
#define VUSB_DEL_DEV            "/sys/bus/usb/drivers/vusb/remove_id"

static int
vusb_assign(int vendor, int product, int add)
{
  char command[64];
  int fd;
  int ret = 0;
  char *path = add ? VUSB_ADD_DEV : VUSB_DEL_DEV;

  fd = open(path, O_WRONLY);
  if (fd == -1) {
    xd_log(LOG_ERR, "%s: failed to open %s", __func__, path);
    return (-1);
  }

  snprintf(command, sizeof (command), "%x %x\n", vendor, product);

  if (write(fd, command, strlen(command)) == -1)
    ret = -1;
  if (close(fd) == -1)
    ret = -1;

  return (ret);
}

/**
 * Build a usbinfo_t from a udev device handle
 *
 * @param udev_dev Udev device handle
 * @param bus Bus ID
 * @param dev Device ID on the bus
 * @param ui The structure to fill (must be already allocated)
 *
 * @return 0 on success
 */
int
usbowls_build_usbinfo(int bus, int dev, int vendor, int product, usbinfo_t *ui)
{
  memset(ui, 0, sizeof(usbinfo_t));

  /* construct xenstore dev id */
  if (dev > 0xFFF) {
    xd_log(LOG_ERR, "bad device id %d", dev);
    return -EINVAL;
  }

  ui->usb_virtid = bus << 12 | (dev & 0xFFF);
  ui->usb_bus = bus;
  ui->usb_device = dev;

  ui->usb_vendor = vendor;
  ui->usb_product = product;

  return 0;
}

static int
get_usbinfo(int bus, int dev, usbinfo_t *ui)
{
  struct udev_enumerate *enumerate;
  struct udev_list_entry *devices, *dev_list_entry;
  struct udev_device *udev_dev;
  char bus_str[16], dev_str[16];
  int vendor, product;

  enumerate = udev_enumerate_new(udev_handle);
  if (!enumerate) {
    xd_log(LOG_ERR, "Can't create enumeration");
    return -ENOMEM;
  }

  snprintf(bus_str, sizeof(bus_str), "%d", bus);
  snprintf(dev_str, sizeof(dev_str), "%d", dev);

  udev_enumerate_add_match_subsystem(enumerate, "usb");
  udev_enumerate_add_match_sysattr(enumerate, "busnum", bus_str);
  udev_enumerate_add_match_sysattr(enumerate, "devnum", dev_str);
  udev_enumerate_scan_devices(enumerate);
  devices = udev_enumerate_get_list_entry(enumerate);
  udev_list_entry_foreach(dev_list_entry, devices) {
    const char *path;

    path = udev_list_entry_get_name(dev_list_entry);
    udev_dev = udev_device_new_from_syspath(udev_handle, path);
    sscanf(udev_device_get_sysattr_value(udev_dev, "idVendor"), "%x", &vendor);
    sscanf(udev_device_get_sysattr_value(udev_dev, "idProduct"), "%x", &product);
    udev_device_unref(udev_dev);
    udev_enumerate_unref(enumerate);
    return usbowls_build_usbinfo(bus, dev, vendor, product, ui);
  }
  udev_enumerate_unref(enumerate);
  return -ENOENT;
}

static void
dump_dev(usbinfo_t *ui)
{
  printf("bus %d device %d vendor %04x product %04x virtid %06x\n", ui->usb_bus, ui->usb_device,
         ui->usb_vendor, ui->usb_product, ui->usb_virtid);
}

/**
 * "Plug" a device to a VM.
 * xenstore_create_usb() will be called to "attach" the device, then
 * vusb_assign() will "assign" it.
 *
 * @param domid The domid of the VM to plug the device to
 * @param bus The bus ID of the device
 * @param device The ID of the device on the bus
 *
 * @return 0 for success, 1 for failure
 */
int
usbowls_plug_device(int domid, int bus, int device)
{
  dominfo_t di;
  usbinfo_t ui;
  int ret;

  ret = xenstore_get_dominfo(domid, &di);
  if (ret != 0) {
    xd_log(LOG_ERR, "Invalid domid %d", domid);
    return 1;
  }
  ret = get_usbinfo(bus, device, &ui);
  if (ret != 0) {
    xd_log(LOG_ERR, "Invalid device %d-%d", bus, device);
    return 1;
  }

  /* FIXME: nicely unbind dom0 drivers on interfaces?
   * Or not, USB supports hot unplug doesn't it? :)
   */

  ret = xenstore_create_usb(&di, &ui);
  if (ret != 0) {
    xd_log(LOG_ERR, "Failed to attach device");
    return 1;
  }

  if (xenstore_wait_for_online(&di, &ui) != 0)
    xd_log(LOG_ERR, "The frontend or the backend didn't go online, continue anyway");

  ret = vusb_assign(ui.usb_vendor, ui.usb_product, 1);
  if (ret != 0) {
    xd_log(LOG_ERR, "Failed to assign device");
    xenstore_destroy_usb(&di, &ui);
    return 1;
  }

  return 0;
}

/**
 * "Unplug" a device from a VM.
 * vusb_unassign() will "unassign" it, then
 * xenstore_create_usb() will be called to "detach" the device.
 *
 * @param domid The domid of the VM to unplug the device from
 * @param bus The bus ID of the device
 * @param device The ID of the device on the bus
 *
 * @return 0 for success, 1 for failure
 */
int
usbowls_unplug_device(int domid, int bus, int device)
{
  dominfo_t di;
  usbinfo_t ui;
  int ret;

  ret = xenstore_get_dominfo(domid, &di);
  if (ret != 0) {
    xd_log(LOG_ERR, "Invalid domid %d", domid);
    return 1;
  }
  ret = get_usbinfo(bus, device, &ui);
  if (ret != 0) {
    xd_log(LOG_ERR, "Invalid device %d-%d", bus, device);
    return 1;
  }

  ret = vusb_assign(ui.usb_vendor, ui.usb_product, 0);
  if (ret != 0) {
    xd_log(LOG_ERR, "Failed to unassign device");
    return 1;
  }

  ret = xenstore_destroy_usb(&di, &ui);
  if (ret != 0) {
    xd_log(LOG_ERR, "Failed to detach device");
    return 1;
  }

  return 0;
}
