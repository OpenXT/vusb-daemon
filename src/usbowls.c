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

#include "project.h"

#define VUSB_ADD_DEV            "/sys/bus/usb/drivers/vusb/new_id"
#define VUSB_DEL_DEV            "/sys/bus/usb/drivers/vusb/remove_id"

static char *xasprintf(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

static struct xs_handle *xs_handle = NULL;
static char *xs_dom0path = NULL;

typedef struct dominfo
{
  int di_domid;
  char *di_name;
  char *di_dompath;
} dominfo_t;

typedef struct usbinfo
{
  int usb_virtid;
  int usb_bus;	/* USB bus in the physical machine */
  int usb_device;	/* USB device in the physical machine */
  int usb_vendor;
  int usb_product;
} usbinfo_t;

enum XenBusStates {
  XB_UNKNOWN, XB_INITTING, XB_INITWAIT, XB_INITTED, XB_CONNECTED,
  XB_CLOSING, XB_CLOSED
};

static void*
xmalloc(size_t size)
{
  void *p;

  if ((p = malloc(size)) == NULL) {
    xd_log(LOG_CRIT, "Out of memory");
    exit(2);
  }

  return (p);
}

/*
 * Allocating formatted string print.
 * The caller is responsible for returning the returned string.
 */
static char *
xasprintf(const char *fmt, ...)
{
  char *s;
  va_list ap;
  int len;

  va_start(ap, fmt);
  len = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);

  s = xmalloc(len + 1);

  va_start(ap, fmt);
  vsprintf(s, fmt, ap);
  va_end(ap);

  return (s);
}

static void
xs_remove(xs_transaction_t xt, char *path)
{
  xd_log(LOG_VERBOSE_DEBUG, "XenStore removing %s", path);
  xs_rm(xs_handle, xt, path);
}

/*
 * Create a new directory in Xenstore
 */
static int
xs_add_dir(xs_transaction_t xt, char *path, int d0, int p0, int d1, int p1)
{
  struct xs_permissions perms[2];

  xd_log(LOG_VERBOSE_DEBUG, "Making %s in XenStore", path);
  if (xs_mkdir(xs_handle, xt, path) == false) {
    xd_log(LOG_ERR, "XenStore error mkdir()ing %s", path);
    return (-1);
  }

  perms[0].perms = p0;
  perms[0].id = d0;
  perms[1].perms = p1;
  perms[1].id = d1;
  if (xs_set_permissions(xs_handle, xt, path, perms, 2) == false) {
    xd_log(LOG_ERR, "XenStore error setting permissions on %s",
	   path);
    xs_remove(xt, path);
    return (-1);
  }

  return (0);
}

static char*
xs_get_keyval(char *path, char *key)
{
  char tmppath[256];
  int len;
  snprintf(tmppath, sizeof(tmppath), "%s/%s", path, key);
  return xs_read(xs_handle, XBT_NULL, tmppath, &len);
}

/*
 * Write a single value into Xenstore.
 */
static int
xs_set_keyval(xs_transaction_t xt, char *path, char *key, char *val)
{
  char tmppath[256];

  if (key != NULL) {
    snprintf(tmppath, sizeof (tmppath), "%s/%s", path, key);
    path = tmppath;
  }
  xd_log(LOG_VERBOSE_DEBUG, "Writing to XenStore: %s = %s", path, val);

  if (xs_write(xs_handle, xt, path, val, strlen(val)) == false) {
    xd_log(LOG_ERR, "XenStore error writing %s", path);
    return (-1);
  }

  return (0);
}

static char*
xs_dev_fepath(dominfo_t *domp, char *type, int devnum)
{
  return (xasprintf("%s/device/%s/%d", domp->di_dompath, type,
		    devnum));
}

static char*
xs_dev_bepath(dominfo_t *domp, char *type, int devnum)
{
  return (xasprintf("%s/backend/%s/%d/%d", xs_dom0path, type,
		    domp->di_domid, devnum));
}

/*
 * Populate Xenstore with the information about a usb device for this domain
 */
static int
xenstore_create_usb(dominfo_t *domp, usbinfo_t *usbp)
{
  char *bepath, *fepath;
  char value[32];
  xs_transaction_t trans;

  xd_log(LOG_DEBUG, "Creating VUSB node for %d.%d",
	 usbp->usb_bus, usbp->usb_device);

  /*
   * Construct Xenstore paths for both the front and back ends.
   */
  fepath = xs_dev_fepath(domp, "vusb", usbp->usb_virtid);
  bepath = xs_dev_bepath(domp, "vusb", usbp->usb_virtid);

  for (;;) {
    trans = xs_transaction_start(xs_handle);

    /*
     * Make directories for both front and back ends
     */
    if (xs_add_dir(trans, bepath, 0, XS_PERM_NONE, domp->di_domid,
		   XS_PERM_READ))
      break;
    if (xs_add_dir(trans, fepath, domp->di_domid, XS_PERM_NONE, 0,
		   XS_PERM_READ))
      break;

    /*
     * Populate frontend device info
     */
    if (xs_set_keyval(trans, fepath, "backend-id", "0"))
      break;
    snprintf(value, sizeof (value), "%d", usbp->usb_virtid);
    if (xs_set_keyval(trans, fepath, "virtual-device", value))
      break;
    if (xs_set_keyval(trans, fepath, "backend", bepath))
      break;
    snprintf(value, sizeof (value), "%d", XB_INITTING);
    if (xs_set_keyval(trans, fepath, "state", value))
      break;

    /*
     * Populate backend device info
     */
    if (xs_set_keyval(trans, bepath, "domain", domp->di_name))
      break;
    if (xs_set_keyval(trans, bepath, "frontend", fepath))
      break;
    snprintf(value, sizeof (value), "%d", XB_INITTING);
    if (xs_set_keyval(trans, bepath, "state", value))
      break;
    if (xs_set_keyval(trans, bepath, "online", "1"))
      break;
    snprintf(value, sizeof (value), "%d", domp->di_domid);
    if (xs_set_keyval(trans, bepath, "frontend-id", value))
      break;
    snprintf(value, sizeof (value), "%d.%d", usbp->usb_bus,
	     usbp->usb_device);
    if (xs_set_keyval(trans, bepath, "physical-device", value))
      break;

    if (xs_transaction_end(xs_handle, trans, false) == false) {
      if (errno == EAGAIN)
	continue;
      break;
    }
    free(fepath);
    free(bepath);

    xd_log(LOG_DEBUG, "Finished creating VUSB node for %d.%d",
	   usbp->usb_bus, usbp->usb_device);

    return (0);
  }

  xs_transaction_end(xs_handle, trans, true);
  xd_log(LOG_ERR, "Failed to write usb info to XenStore");
  free(fepath);
  free(bepath);
  return (-1);
}

static void
get_xb_states(dominfo_t *domp, usbinfo_t *usbp, int *frontst, int *backst)
{
  char *bepath, *fepath;
  char *v;
  *frontst = XB_UNKNOWN;
  *backst  = XB_UNKNOWN;

  fepath = xs_dev_fepath(domp, "vusb", usbp->usb_virtid);
  bepath = xs_dev_bepath(domp, "vusb", usbp->usb_virtid);
  v = xs_get_keyval(fepath, "state");
  if (v) {
    *frontst = atoi(v);
    free(v);
  }
  v = xs_get_keyval(bepath, "state");
  if (v) {
    *backst = atoi(v);
    free(v);
  }
  free(fepath);
  free(bepath);
}

static int
test_offline(dominfo_t *domp, usbinfo_t *usbp)
{
  int f, b;
  get_xb_states(domp, usbp, &f, &b);
  printf("%d %d\n", f, b);
  return (f == XB_UNKNOWN || f == XB_CLOSED) &&
         (b == XB_UNKNOWN || b == XB_CLOSED);
}

/*
 * Remove information about a usb device for this domain from Xenstore
 */
static int
xenstore_destroy_usb(dominfo_t *domp, usbinfo_t *usbp)
{
  char value[32];
  char *bepath;
  char *fepath;
  int i;

  xd_log(LOG_INFO, "Deleting VUSB node %d for %d.%d",
	 usbp->usb_virtid, usbp->usb_bus, usbp->usb_device);

  bepath = xs_dev_bepath(domp, "vusb", usbp->usb_virtid);
  fepath = xs_dev_fepath(domp, "vusb", usbp->usb_virtid);

  /* Notify the backend that the device is being shut down */
  xs_set_keyval(XBT_NULL, bepath, "online", "0");
  xs_set_keyval(XBT_NULL, bepath, "physical-device", "0.0");
  snprintf(value, sizeof (value), "%d", XB_CLOSING);
  xs_set_keyval(XBT_NULL, bepath, "state", value);

  /* TODO: NUKE SLEEPS!! */
  for (i = 0; i < 30; ++i) {
    usleep(100000);
    if (test_offline(domp, usbp)) {
      xs_rm(xs_handle, XBT_NULL, fepath);
      xs_rm(xs_handle, XBT_NULL, bepath);
      break;
    }
  }


  free(bepath);
  free(fepath);

  return (0);
}

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

static int
get_dominfo(int domid, dominfo_t *di)
{
  di->di_domid = domid;
  di->di_dompath = xs_get_domain_path(xs_handle, di->di_domid);
  if (!di->di_dompath) {
    xd_log(LOG_ERR, "Could not get domain %d path from xenstore", domid);
    return -ENOENT;
  }
  di->di_name = xasprintf("Domain-%d", domid);
  return 0;
}

static int
get_usbinfo(int bus, int dev, usbinfo_t *ui)
{
  struct udev *udev;
  struct udev_enumerate *enumerate;
  struct udev_list_entry *devices, *dev_list_entry;
  struct udev_device *udev_dev;
  char bus_str[16], dev_str[16];
  int found = 0;

  memset(ui, 0, sizeof(usbinfo_t));

  /* construct xenstore dev id */
  if (dev > 0xFFF) {
    xd_log(LOG_ERR, "bad device id %d", dev);
    return -EINVAL;
  }

  ui->usb_virtid = bus << 12 | (dev & 0xFFF);
  ui->usb_bus = bus;
  ui->usb_device = dev;

  /* udev scan */
  udev = udev_new();
  if (!udev) {
    xd_log(LOG_ERR, "Can't create udev");
    return -ENOMEM;
  }
  enumerate = udev_enumerate_new(udev);
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
    udev_dev = udev_device_new_from_syspath(udev, path);
    sscanf(udev_device_get_sysattr_value(udev_dev, "idVendor"), "%x", &ui->usb_vendor);
    sscanf(udev_device_get_sysattr_value(udev_dev, "idProduct"), "%x", &ui->usb_product);
    udev_device_unref(udev_dev);
    udev_enumerate_unref(enumerate);
    udev_unref(udev);
    return 0;
  }
  udev_enumerate_unref(enumerate);
  udev_unref(udev);
  return -ENOENT;
}

static void
dump_dev(usbinfo_t *ui)
{
  printf("bus %d device %d vendor %04x product %04x virtid %06x\n", ui->usb_bus, ui->usb_device,
         ui->usb_vendor, ui->usb_product, ui->usb_virtid);
}

static void
list_domain_devs(dominfo_t *domp)
{
  char xpath[256], **devs;
  int domid = domp->di_domid;
  int count,i;

  snprintf(xpath, sizeof(xpath), "/local/domain/0/backend/vusb/%d", domid);
  devs = xs_directory(xs_handle, XBT_NULL, xpath, &count);
  if (devs) {
    for (i = 0; i < count; ++i) {
      int virtid = atoi(devs[i]);
      int bus = virtid >> 12;
      int dev = virtid & 0xFFF;
      char *bepath = xs_dev_bepath(domp, "vusb", virtid);
      char *online = xs_get_keyval(bepath, "online");
      if (online && !strcmp(online, "1"))
        printf("%d %d\n", bus, dev);
      free(online);
      free(bepath);
    }
    free(devs);
  }
  fflush(stdout);
}

int
usbowls_xenstore_init(void)
{
  if (xs_handle == NULL) {
    xs_handle = xs_daemon_open();
  }

  if (xs_handle == NULL) {
    xd_log(LOG_ERR, "Failed to connect to xenstore");
    return 1;
  }

  if (xs_dom0path == NULL) {
    xs_dom0path = xs_get_domain_path(xs_handle, 0);
  }

  if (xs_dom0path == NULL) {
    xd_log(LOG_ERR, "Could not get domain 0 path from XenStore");
     return 1;
  }

  return 0;
}

int
usbowls_xenstore_deinit(void)
{
  xs_daemon_close(xs_handle);
  xs_handle = NULL;

  return 0;
}

int
usbowls_plug_device(int domid, int bus, int device)
{
  dominfo_t di;
  usbinfo_t ui;
  int ret;

  ret = get_dominfo(domid, &di);
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
   * USB supports hot unplug doesn't it? :)
   */

  ret = xenstore_create_usb(&di, &ui);
  if (ret != 0) {
    xd_log(LOG_ERR, "Failed to attach device");
    return 1;
  }

  /* FIXME: wait for the backend to be connected (xs_watch) */

  ret = vusb_assign(ui.usb_vendor, ui.usb_product, 1);
  if (ret != 0) {
    xd_log(LOG_ERR, "Failed to assign device");
    xenstore_destroy_usb(&di, &ui);
    return 1;
  }

  return 0;
}

int
usbowls_unplug_device(int domid, int bus, int device)
{
  dominfo_t di;
  usbinfo_t ui;
  int ret;

  ret = get_dominfo(domid, &di);
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
