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

#ifndef __PROJECT_H__
#define __PROJECT_H__

#include "config.h"

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif
#include <time.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(HAVE_SYS_INT_TYPES_H)
#include <sys/int_types.h>
#endif

#include <syslog.h>
#include <fcntl.h>
#include <stdarg.h>
#include <getopt.h>
#include <xenstore.h>
/* #include <xcxenstore.h> */
#include <libudev.h>
#include <usb.h>
/* #include <libusb-1.0/libusb.h> */

#include "rpcgen/xenmgr_vm_client.h"
#include "rpcgen/xenmgr_client.h"
#include "list.h"
#include "classes.h"

#define UUID_LENGTH 37 /* Includes the string terminator */
#define DOM0_DOMID  0
#define DOM0_UUID   "00000000-0000-0000-0000-000000000000"
#define UIVM_UUID   "00000000-0000-0000-0000-000000000001"
#define UIVM_PATH   "/vm/00000000_0000_0000_0000_000000000001"

#define XENMGR      "com.citrix.xenclient.xenmgr"
#define XENMGR_OBJ  "/"

#define DEV_STATE_ERROR       -1 /* Cannot find device */
#define DEV_STATE_UNUSED      0  /* Device not in use by any VM */
#define DEV_STATE_ASSIGNED    1  /* Assigned to another VM which is off */
#define DEV_STATE_IN_USE      2  /* Assigned to another VM which is running */
#define DEV_STATE_BLOCKED     3  /* Blocked by policy for this VM */
#define DEV_STATE_THIS        4  /* In use by this VM */
#define DEV_STATE_THIS_ALWAYS 5  /* In use by this VM and flagged "always" */
#define DEV_STATE_ALWAYS_ONLY 6  /* Flagged as "always" assigned to this VM, but not currently in use */
#define DEV_STATE_PLATFORM    7  /* Special platform device, listed purely for information */
#define DEV_STATE_HID_DOM0    8  /* HiD device assigned to dom0 */
#define DEV_STATE_HID_ALWAYS  9  /* HiD device currently assigned to dom0, but always assigned to another VM */
#define DEV_STATE_CD_DOM0     10 /* External CD drive assigned to dom0 */
#define DEV_STATE_CD_ALWAYS   11 /* External CD drive currently assigned to dom0, but always assigned to another VM */

#define xd_log(I, ...) { fprintf(stderr, ##__VA_ARGS__); fprintf(stderr, "\n"); }

typedef struct {
  struct list_head list;
  int domid;
  char *uuid;
} vm_t;

typedef struct {
  struct list_head list;
  int busid;
  int devid;
  int vendorid;
  int deviceid;
  char *shortname;
  char *longname;
  char *sysname;
  vm_t *vm;
} device_t;

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

/* Generate a device ID
 * param    bus_num              number of bus device is on
 * param    dev_num              device number within bus
 * return                        device id
 */
static int makeDeviceId(int bus_num, int dev_num)
{
  return ((bus_num - 1) << 7) + (dev_num - 1);
}

static void makeBusDevPair(int devid, int *bus_num, int *dev_num)
{
  *bus_num = (devid >> 7) + 1;
  *dev_num = (devid & 0x7F) + 1;
}

/* char *xasprintf(const char *fmt, ...) __attribute__ ((format (printf, 1, 2))); */
struct xs_handle *xs_handle;
char *xs_dom0path;

xcdbus_conn_t *g_xcbus;
vm_t vms;
device_t devices;

int   usbowls_xenstore_init(void);
int   usbowls_xenstore_deinit(void);
int   usbowls_plug_device(int domid, int bus, int device);
int   usbowls_unplug_device(int domid, int bus, int device);

void  rpc_init(void);

int   udev_init(void);
void  udev_event(void);
int   udev_maybe_add_device(struct udev_device *dev);
int   udev_fill_devices(void);
int   udev_bind_device_to_dom0(struct udev_device *dev);

device_t*   device_lookup(int busid, int devid);
device_t*   device_add(int busid, int devid, int vendorid, int deviceid,
		       char *shortname, char *longname, char *sysname);
int         device_del(int  busid, int  devid);
int         device_bind_to_dom0(int busid, int devid);
int         device_bind_to_dom0_by_sysname(const char *name);
char*       device_type(unsigned char class, unsigned char subclass,
		  unsigned char protocol);

vm_t* vm_lookup(const int domid);
vm_t* vm_lookup_by_uuid(const char *uuid);
int   vm_add(const int domid, const char *uuid);
int   vm_del(const int domid);

int   xenstore_create_usb(dominfo_t *domp, usbinfo_t *usbp);
int   xenstore_destroy_usb(dominfo_t *domp, usbinfo_t *usbp);
char* xenstore_dom_read (unsigned int domid, const char *format, ...);
int   xenstore_get_dominfo(int domid, dominfo_t *di);
void  xenstore_get_xb_states(dominfo_t *domp, usbinfo_t *usbp, int *frontst, int *backst);
void  xenstore_list_domain_devs(dominfo_t *domp);
int   xenstore_init(void);
int   xenstore_deinit(void);

int   policy_init(void);
int   policy_auto_assign(device_t *device);
int   policy_set_sticky(int dev);
int   policy_unset_sticky(int dev);

#endif
