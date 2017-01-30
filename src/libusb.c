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

#define BMATTRIBUTES_BULK               0x02
#define BENDPOINTADDRESS_IN             0x80
#define TYPICAL_NIC_PACKET_SIZE         0x0200
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

/**
 * Identify vendor-specific interfaces with endpoints that support
 * bulk data transfers both in and out with a packet size of at least
 * TYPICAL_NIC_PACKET_SIZE (512). Though all the USB NICs that were
 * tested had such an endpoint and none of the other USB devices did,
 * It is possible that checking for NICs in this manner will result
 * in false positives or negatives.
 */
static bool
libusb_is_unknown_bulk_transfer_interface(struct usb_interface_descriptor *interface)
{
  int i;
  bool has_bulk_in = false;
  bool has_bulk_out = false;

  if (interface->bInterfaceClass == VENDOR_SPECIFIC_CLASS)
    for (i = 0; i < interface->bNumEndpoints; i++)
    {
      struct usb_endpoint_descriptor *endpoint = &interface->endpoint[i];

      if (endpoint->bmAttributes == BMATTRIBUTES_BULK && endpoint->wMaxPacketSize >= TYPICAL_NIC_PACKET_SIZE)
      {
        if (endpoint->bEndpointAddress & BENDPOINTADDRESS_IN)
          has_bulk_in = true;
        else
          has_bulk_out = true;
        if (has_bulk_in && has_bulk_out)
          return true;
      }
    }
  return false;
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
          xd_log(LOG_WARN, "Aborting libusb_find_more_about_nic due to exceeding the endpoint limit");
          return;
        }

        if (libusb_is_unknown_bulk_transfer_interface(interface_descriptor) ||
            libusb_is_ethernet_interface(interface_descriptor) ||
            libusb_is_wireless_interface(interface_descriptor))
          device->type |= NIC;
        if (libusb_is_bluetooth_interface(interface_descriptor))
          device->type |= BLUETOOTH;
      }
    }
  }
}
