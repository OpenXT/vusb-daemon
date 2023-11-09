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
 * @file   usbmanager.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Tue Nov  3 13:38:07 2015
 *
 * @brief  USB platform management bits
 *
 * Functions unrelated to USB "passthrough", but living here because
 * OpenXT doesn't have a non-virtual USB management daemon.
 */

#include "project.h"

/* CTXUSB_DAEMON dbus object implementation */
#include "rpcgen/ctxusb_daemon_server_obj.h"

/**
 * This should be called after a new device gets detected and analyzed.
 *
 * @param device The device that just got added
 */
void usbmanager_device_added(device_t *device)
{
  int dev_id;

  if (g_xcbus == NULL) {
    return;
  }

  dev_id = device_make_id(device->busid, device->devid);
  notify_com_citrix_xenclient_usbdaemon_device_added(g_xcbus,
                                                     USBDAEMON,
                                                     USBDAEMON_OBJ,
                                                     dev_id);
  if (device->type & OPTICAL)
    notify_com_citrix_xenclient_usbdaemon_optical_device_detected(g_xcbus,
                                                                  USBDAEMON,
                                                                  USBDAEMON_OBJ);
  notify_com_citrix_xenclient_usbdaemon_devices_changed(g_xcbus,
							USBDAEMON,
							USBDAEMON_OBJ);
}

/**
 * This should be called after a new device gets removed.
 */
void usbmanager_device_removed(void)
{
  if (g_xcbus == NULL) {
    return;
  }

  notify_com_citrix_xenclient_usbdaemon_devices_changed(g_xcbus,
							USBDAEMON,
							USBDAEMON_OBJ);
}
