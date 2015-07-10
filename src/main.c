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

#if 0
static int
disable_autoprobe(void)
{
  int fd;

  fd = open("/sys/bus/usb/drivers_autoprobe", O_WRONLY);
  if (fd < 0)
    return -1;
  write(fd, "0", 1);
  close(fd);

  return 0;
}
#endif

int
main() {
  int ret;
  vm_t *vm;
  struct timeval tv;
  fd_set readfds;
  fd_set writefds;
  fd_set exceptfds;
  int nfds;
  int udevfd;

  /* Init global VMs and devices lists */
  INIT_LIST_HEAD(&vms.list);
  INIT_LIST_HEAD(&devices.list);

  /* Add dom0 to the list of VMs */
  vm = malloc(sizeof(vm_t));
  vm->domid = DOM0_DOMID;
  vm->uuid = DOM0_UUID;
  list_add(&vm->list, &vms.list);

  /* Add the USB devices to the global device list */
  udev_fill_devices();

  /* Initialize xenstore handle in usbowls */
  ret = usbowls_xenstore_init();
  if (ret != 0)
    return ret;

  /* FIXME: merge with the previous xenstore init */
  xenstore_init();

  /* Setup the dbus server */
  rpc_init();

  /* Why would we do that? */
  /* Disable driver autoprobing */
  /* if (disable_autoprobe() != 0) { */
  /*   xd_log(LOG_ERR, "Unable to disable autoprobing"); */
  /*   return -1; */
  /* } */

  /* Setup the udev monitor */
  udevfd = udev_init();
  if (udevfd < 0) {
    xd_log(LOG_ERR, "Unable to initialize the udev monitor");
    return -1;
  }

  /* Setup libusb */
  /* if (libusb_init(NULL) != 0) { */
  /*   xd_log(LOG_ERR, "Unable to initialize libusb"); */
  /*   return -1; */
  /* } */

  /* Main loop */
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
    FD_ZERO(&readfds);
    FD_SET(udevfd, &readfds);
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    ret = select(udevfd + 1, &readfds, NULL, NULL, &tv);
    if (ret > 0 && FD_ISSET(udevfd, &readfds))
      udev_event();
  }

  /* In the future, the while loop may break on critical error,
     so cleaning up here may be a good idea */
  ret = usbowls_xenstore_deinit();

  /* libusb_exit(NULL); */

  /* FIXME: free VMs and devices lists */

  return ret;
}
