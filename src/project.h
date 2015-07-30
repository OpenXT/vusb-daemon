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
 * @file project.h
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date 20 Jul 2015
 * @brief Local project header
 *
 * Header local to the project that shouldn't be exported.
 * Included by virtually every .c file in the project
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

#include "rpcgen/db_client.h"
#include "rpcgen/input_daemon_client.h"
#include "rpcgen/xenmgr_client.h"
#include "rpcgen/xenmgr_vm_client.h"
#include "list.h"
#include "classes.h"

#include "policy.h"
#include "db.h"

#define UUID_LENGTH 37 /**< Length of UUIDs, including the string terminator */
#define DOM0_DOMID  0  /**< Dom0's domid... */
#define DOM0_UUID   "00000000-0000-0000-0000-000000000000" /**< Dom0's UUID */
#define UIVM_UUID   "00000000-0000-0000-0000-000000000001" /**< UIVM's UUID */
#define UIVM_PATH   "/vm/00000000_0000_0000_0000_000000000001" /**< UIVM's xenstore path */

#define XENMGR      "com.citrix.xenclient.xenmgr" /**< The dbus name of xenmgr*/
#define XENMGR_OBJ  "/"                           /**< The main dbus object of xenmgr*/

/**
 * The (stupid) logging macro
 */
#define xd_log(I, ...) { fprintf(stderr, ##__VA_ARGS__); fprintf(stderr, "\n"); }

/**
 * @brief VM structure
 *
 * VM structure used to keep a linked list of the running (or not) VMs.
 */
typedef struct {
  struct list_head list; /**< Linux-kernel-style list item */
  int domid;             /**< VM domid */
  char *uuid;            /**< VM UUID */
} vm_t;

/**
 * @brief Device structure
 *
 * Device structure used to keep a linked list of the USB devices
 * present in the system, and their assigned VM
 */
typedef struct {
  struct list_head list; /**< Linux-kernel-style list item */
  int busid;             /**< Device bus */
  int devid;             /**< Device ID on the bus */
  int vendorid;          /**< Device vendor ID */
  int deviceid;          /**< Device device ID */
  char *shortname;       /**< Name shown in the UI, usually sysattr["product"] */
  char *longname;        /**< Longer name shown nowhere I know of, usually sysattr["manufacturer"] */
  char *sysname;         /**< Name in sysfs */
  vm_t *vm;              /**< VM currently using the device, or NULL for dom0 */
  int type;              /**< Type of the device, can be multiple types OR-ed together. see policy.h */
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
  int usb_bus;           /**< USB bus in the physical machine */
  int usb_device;        /**< USB device in the physical machine */
  int usb_vendor;
  int usb_product;
} usbinfo_t;

enum XenBusStates {
  XB_UNKNOWN, XB_INITTING, XB_INITWAIT, XB_INITTED, XB_CONNECTED,
  XB_CLOSING, XB_CLOSED
};

/**
 * @brief Generate a device ID
 *
 * Generate a single ID from the bus and device IDs
 * @param bus_num Device bus
 * @param dev_num Device ID on the bus
 */
static int makeDeviceId(int bus_num, int dev_num)
{
  return ((bus_num - 1) << 7) + (dev_num - 1);
}

/**
 * @brief Get the bus and device IDs of a device
 *
 * Extract bus and device IDs from a single device ID
 * @param devid   The single ID
 * @param bus_num Resulting device bus
 * @param dev_num Resulting Device ID
 */
static void makeBusDevPair(int devid, int *bus_num, int *dev_num)
{
  *bus_num = (devid >> 7) + 1;
  *dev_num = (devid & 0x7F) + 1;
}

struct xs_handle *xs_handle; /**< The global xenstore handle, initialized by xenstore_init() */
xcdbus_conn_t *g_xcbus;      /**< The global dbus (libxcdbus) handle, initialized by rpc_init() */
vm_t vms;                    /**< The global list of VMs, handled by vm.c */
device_t devices;            /**< The global list of devices, handled by device.c */
struct udev *udev_handle;    /**< The global udev handle, initialized by udev_init() */

int   usbowls_plug_device(int domid, int bus, int device);
int   usbowls_unplug_device(int domid, int bus, int device);
int   usbowls_build_usbinfo(int bus, int dev, int vendor, int product, usbinfo_t *ui);

void  rpc_init(void);

int   udev_init(void);
void  udev_event(void);
void  udev_fill_devices(void);

device_t* device_lookup(int busid, int devid);
device_t* device_lookup_by_attributes(int vendorid, int deviceid, char *serial);
device_t* device_add(int busid, int devid, int vendorid, int deviceid,
                     char *shortname, char *longname, char *sysname);
int       device_del(int  busid, int  devid);
char*     device_type(unsigned char class, unsigned char subclass,
                      unsigned char protocol);
int       device_unplug_all_from_vm(int domid);


vm_t* vm_lookup(const int domid);
vm_t* vm_lookup_by_uuid(const char *uuid);
vm_t* vm_add(const int domid, const char *uuid);
int   vm_del(const int domid);

int   xenstore_create_usb(dominfo_t *domp, usbinfo_t *usbp);
int   xenstore_destroy_usb(dominfo_t *domp, usbinfo_t *usbp);
int   xenstore_wait_for_online(dominfo_t *di, usbinfo_t *ui);
int   xenstore_wait_for_offline(dominfo_t *di, usbinfo_t *ui);
char* xenstore_dom_read (unsigned int domid, const char *format, ...);
int   xenstore_get_dominfo(int domid, dominfo_t *di);
void  xenstore_get_xb_states(dominfo_t *domp, usbinfo_t *usbp, int *frontst, int *backst);
void  xenstore_list_domain_devs(dominfo_t *domp);
int   xenstore_init(void);
void  xenstore_deinit(void);

int   policy_init(void);
bool  policy_is_allowed(device_t *device, vm_t *vm);
int   policy_set_sticky(int dev);
int   policy_unset_sticky(int dev);
char* policy_get_sticky_uuid(int dev);
int   policy_auto_assign_new_device(device_t *device);
int   policy_auto_assign_devices_to_new_vm(vm_t *vm);

#endif
