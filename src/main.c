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
 * @file   main.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Thu Jul 30 13:24:08 2015
 *
 * @brief  vUSB daemon
 *
 * Daemon that handles USB device passthrough
 */

#include "project.h"

static void fill_vms()
{
  GPtrArray *paths;
  int i;

  /* Add dom0 to the list of VMs */
  vm_add(DOM0_DOMID, DOM0_UUID);

  /* Get all the (other) VMs from xenmgr */
  /* If xenmgr is not started yet, this will fail,
     which is fine since we'll get new VM notifications once xenmgr is up and runnning */
  com_citrix_xenclient_xenmgr_list_vms_(g_xcbus, XENMGR, XENMGR_OBJ, &paths);
  if (!com_citrix_xenclient_xenmgr_list_vms_(g_xcbus, XENMGR, XENMGR_OBJ, &paths)) {
    xd_log(LOG_WARNING, "Unable to get the list of VMs");
    return;
  }

  /* Get their domid and add them to the list */
  for (i = 0; i < paths->len; ++i) {
    const char *path = g_ptr_array_index(paths, i);
    int domid;

    if (!property_get_com_citrix_xenclient_xenmgr_vm_domid_(g_xcbus, XENMGR, path, &domid)) {
      xd_log(LOG_ERR, "Unable to get the domid of a VM");
      return;
    }

    vm_add(domid, path + 4);
    /* At this point, if the VM is running (domid > -1) we could run
     * the sticky rules, but I don't think we should */
  }

  g_ptr_array_free(paths, TRUE);
}

int dbus_pre_select(int nfds, fd_set *readfds, fd_set *writefds,
                    fd_set *exceptfds)
{
  if (g_xcbus == NULL) {
    return nfds;
  }

  return xcdbus_pre_select(g_xcbus, nfds, readfds, writefds, exceptfds);
}

void dbus_post_select(int nfds, fd_set *readfds, fd_set *writefds,
                     fd_set *exceptfds)
{
  if (g_xcbus == NULL) {
    return;
  }

  xcdbus_post_select(g_xcbus, nfds, readfds, writefds, exceptfds);
}

int
main(int argc, char *argv[]) {
  int ret;
  fd_set readfds;
  fd_set writefds;
  fd_set exceptfds;
  int nfds;
  int xsfd;
  int udevfd;
  int dbus = 1;

  /* init libusb */
  usb_init();

  /* Init global VMs and devices lists */
  INIT_LIST_HEAD(&vms.list);
  INIT_LIST_HEAD(&devices.list);

  if (argc > 1 && strcmp(argv[1], "stub-mode") == 0) {
    xd_log(LOG_INFO, "Running in stub-mode (no D-Bus)");
    dbus = 0;
    g_xcbus = NULL;
  } else {
    xd_log(LOG_INFO, "Running in full mode with D-Bus");
  }

  xs_handle = NULL;
  xsfd = xenstore_init();
  if (xsfd == -1)
    return -1;

  if (dbus) {
    /* Setup dbus */
    rpc_init();

    /* Load the policy bits */
    ret = policy_init();
    if (ret != 0) {
      xd_log(LOG_ERR, "Unable to initialize the policy bits");
      return -1;
    }

    xenstore_state_handle();

    /* Populate the VM list */
    fill_vms();
  }

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

  /* Populate the USB device list */
  udev_fill_devices();

  ret = xsdev_watch_init();
  if (ret == 0) {
    xd_log(LOG_ERR, "Unable to initialize xenstore device watch");
  }

  ret = xsdev_fill();
  if (ret == 0) {
    xd_log(LOG_ERR, "Unable to populate devices from xenstore");
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

    FD_SET(udevfd, &readfds);
    FD_SET(xsfd, &readfds);
    nfds = xsfd > udevfd ? xsfd : udevfd;
    nfds = nfds + 1;

    nfds = dbus_pre_select(nfds, &readfds, &writefds, &exceptfds);
    ret = select(nfds, &readfds, &writefds, &exceptfds, NULL);
    dbus_post_select(nfds, &readfds, &writefds, &exceptfds);

    if (ret > 0 && FD_ISSET(udevfd, &readfds))
      udev_event();

    if (ret > 0 && FD_ISSET(xsfd, &readfds))
      xenstore_event();
  }

  /* In the future, the while loop may break on critical error,
     so cleaning up here may be a good idea */
  xenstore_deinit();
  /* libusb_exit(NULL); */
  udev_unref(udev_handle);

  /* FIXME: free VMs and devices lists */

  return ret;
}
