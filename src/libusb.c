/*
 * Copyright (c) 2017 Assured Information Security, Inc.
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
 * @file   libusb.c
 * @author Troy Crosley <crosleyt@ainfosec.com>
 * @date   Fri Feb 03 10:53:45 2017
 *
 * @brief  libusb interaction
 *
 * Functions that usb libusb to find more about the device type
 */

#include "project.h"

#define MAX_ENDPOINTS                   1000

static bool
libusb_is_ethernet_interface(struct usb_interface_descriptor *interface)
{
  return (interface->bInterfaceClass == COMMUNICATIONS_CLASS &&
    interface->bInterfaceSubClass == ETHERNET_NETWORKING_SUBCLASS);
}

static bool
libusb_is_wireless_interface(struct usb_interface_descriptor *interface)
{
  return (interface->bInterfaceClass == WIRELESS_CLASS &&
    (interface->bInterfaceSubClass != RADIO_FREQUENCY_SUBCLASS ||
    interface->bInterfaceProtocol != BLUETOOTH_PROTOCOL));
}

static bool
libusb_is_bluetooth_interface(struct usb_interface_descriptor *interface)
{
  return (interface->bInterfaceClass == WIRELESS_CLASS &&
    interface->bInterfaceSubClass == RADIO_FREQUENCY_SUBCLASS &&
    interface->bInterfaceProtocol == BLUETOOTH_PROTOCOL);
}

static struct usb_device *
libusb_findDevice(int vendorid, int productid)
{
  struct usb_bus *bus;
  struct usb_device *dev;
  struct usb_bus *busses;

  usb_find_busses();
  usb_find_devices();
  busses = usb_get_busses();

  for (bus = busses; bus; bus = bus->next)
    for (dev = bus->devices; dev; dev = dev->next)
      if ((dev->descriptor.idVendor == vendorid) && (dev->descriptor.idProduct == productid))
        return dev;

  return NULL;
}

/**
 * Determine if the device is a possible NIC or Bluetooth device.
 * It parses the USB descriptors, which can have multiple
 * configurations, which can have multiple interfaces, which can have
 * multiple "altSettings," which can have multiple endpoints.
 */
void
libusb_find_more_about_nic(device_t *device)
{
  int i, j, k;
  int totalEndpoints = 0;
  struct usb_device *libusb_device = libusb_findDevice(device->vendorid, device->deviceid);

  if (!libusb_device)
  {
    xd_log(LOG_WARNING, "Unable to find device with vendor ID %04x and device ID %04x. Was it removed?", device->vendorid, device->deviceid);
    return;
  }

  for (i = 0; i < libusb_device->descriptor.bNumConfigurations; i++)
  {
    struct usb_config_descriptor *config = &libusb_device->config[i];

    for(j = 0; j < config->bNumInterfaces; j++)
    {
      struct usb_interface *interface = &config->interface[j];

      for (k = 0; k < interface->num_altsetting; k++)
      {
        struct usb_interface_descriptor *interface_descriptor = &interface->altsetting[k];

        /* This is just an arbitrary loop limit to make the nested for-loops less scary */
        totalEndpoints++;
        if (totalEndpoints > MAX_ENDPOINTS)
        {
          xd_log(LOG_WARNING, "Aborting libusb_find_more_about_nic due to exceeding the endpoint limit");
          return;
        }

        // TODO: some nics will be marked with the VENDOR_SPECIFIC class,
        // which means they won't match either of the below checks. an
        // additional method is needed to properly ID these devices.
        if (libusb_is_ethernet_interface(interface_descriptor) ||
            libusb_is_wireless_interface(interface_descriptor))
          device->type |= NIC;
        if (libusb_is_bluetooth_interface(interface_descriptor))
          device->type |= BLUETOOTH;
      }
    }
  }
}
