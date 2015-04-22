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

#define SERVICE "com.citrix.xenclient.usbdaemon"
#define SERVICE_OBJ_PATH "/"

static DBusConnection  *g_dbus_conn = NULL;
static DBusGConnection *g_glib_dbus_conn = NULL;

/*********************************************/
/** CTXUSB_DAEMON dbus object implementation */
/******************vvvvvvvvv******************/
#include "rpcgen/ctxusb_daemon_server_obj.h"

void rpc_init(void)
{
    CtxusbDaemonObject *server_obj = NULL;
    /* have to initialise glib type system */
    g_type_init();

    g_glib_dbus_conn = dbus_g_bus_get(DBUS_BUS_SYSTEM, NULL);
    if (!g_glib_dbus_conn) {
        xd_log(LOG_ERR, "no bus");
        exit(1);
    }
    g_dbus_conn = dbus_g_connection_get_connection(g_glib_dbus_conn);
    g_xcbus = xcdbus_init2(SERVICE, g_glib_dbus_conn);
    if (!g_xcbus) {
        xd_log(LOG_ERR, "failed to init dbus connection / grab service name");
        exit(1);
    }
    /* export server object */
    server_obj = ctxusb_daemon_export_dbus(g_glib_dbus_conn, SERVICE_OBJ_PATH);
    if (!server_obj) {
        xd_log(LOG_ERR, "failed to export server object");
        exit(1);
    }
}

/* Generate a device ID
 * param    bus_num              number of bus device is on
 * param    dev_num              device number within bus
 * return                        device id
 */
int makeDeviceId(int bus_num, int dev_num)
{
  return ((bus_num - 1) << 7) + (dev_num - 1);
}

void makeBusDevPair(int devid, int *bus_num, int *dev_num)
{
  *bus_num = (devid >> 7) + 1;
  *dev_num = (devid & 0x7F) + 1;
}

int add_vm(int domid)
{
  char *uuid;
  struct list_head *pos;
  vm_t *vm;

  list_for_each(pos, &vms.list) {
    vm = list_entry(pos, vm_t, list);
    if (vm->domid == domid) {
          xd_log(LOG_ERR, "new VM already registered: %d", domid);
	  return 0;
    }
  }
  vm = malloc(sizeof(vm_t));
  vm->domid = domid;
  uuid = xenstore_dom_read(domid, "vm");
  if (uuid == NULL) {
    xd_log(LOG_ERR, "Couldn't find UUID for domid %d", domid);
    return -1;
  }
  vm->uuid = malloc(UUID_LENGTH);
  strncpy(vm->uuid, uuid + 4, UUID_LENGTH);
  free(uuid);
  list_add(&vm->list, &vms.list);

  return 0;
}

int del_vm(int domid)
{
  char *uuid;
  struct list_head *pos;
  vm_t *vm;

  list_for_each(pos, &vms.list) {
    vm = list_entry(pos, vm_t, list);
    if (vm->domid == domid) {
      break;
    }
  }
  if (vm->domid == domid) {
    list_del(pos);
  } else {
    xd_log(LOG_ERR, "VM not found: %d", domid);
    return -1;
  }

  return 0;
}

gboolean ctxusb_daemon_set_policy_domuuid(
    CtxusbDaemonObject *this,
    const char *uuid,
    const char *policy, GError **error)
{
    return FALSE;
}

gboolean ctxusb_daemon_get_policy_domuuid(
    CtxusbDaemonObject *this,
    const char *uuid,
    char **value, GError **error)
{
    return FALSE;
}

gboolean ctxusb_daemon_new_vm(CtxusbDaemonObject *this,
                              gint IN_dom_id, GError **error)
{
  int ret;

  ret = add_vm(IN_dom_id);

  return ret ? FALSE : TRUE;
}

gboolean ctxusb_daemon_vm_stopped(CtxusbDaemonObject *this,
                                  gint IN_dom_id, GError **error)
{
  int ret;

  ret = del_vm(IN_dom_id);

  return ret ? FALSE : TRUE;
}

gboolean ctxusb_daemon_list_devices(CtxusbDaemonObject *this,
                                    GArray* *OUT_devices, GError **error)
{
  GArray *devArray;
  struct list_head *pos;
  device_t *device;
  int id;

  devArray = g_array_new(FALSE, FALSE, sizeof(gint));

  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    id = makeDeviceId(device->busid, device->devid);
    g_array_append_val(devArray, id);
  }

  *OUT_devices = devArray;

  return TRUE;
}

gboolean ctxusb_daemon_get_device_info(CtxusbDaemonObject *this,
                                       gint IN_dev_id, const char* IN_vm_uuid,
                                       char* *OUT_name, gint *OUT_state, char* *OUT_vm_assigned, char* *OUT_detail, GError **error)
{
  struct list_head *pos;
  device_t *device;
  int busid, devid;

  printf("ctxusb_daemon_get_device_info %d %s\n", IN_dev_id, IN_vm_uuid);

  makeBusDevPair(IN_dev_id, &busid, &devid);
  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      break;
    }
  }
  if (device->busid != busid || device->devid != devid) {
    xd_log(LOG_ERR, "Device not found: %d", IN_dev_id);
    return FALSE;
  }
  *OUT_name = g_strdup(device->shortname);
  *OUT_state = 0;
  if (device->vm != NULL) {
    *OUT_state = 2;
    *OUT_vm_assigned = g_strdup(device->vm->uuid);
  } else {
    *OUT_state = 0;
    *OUT_vm_assigned = g_strdup("");
  }
  *OUT_detail = g_strdup(device->longname);

  return TRUE;
}

gboolean ctxusb_daemon_assign_device(CtxusbDaemonObject *this,
                                     gint IN_dev_id, const char* IN_vm_uuid, GError **error)
{
  struct list_head *pos;
  device_t *device;
  vm_t *vm;
  int busid, devid;
  int ret;

  makeBusDevPair(IN_dev_id, &busid, &devid);
  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      break;
    }
  }
  list_for_each(pos, &vms.list) {
    vm = list_entry(pos, vm_t, list);
    if (!strncmp(vm->uuid, IN_vm_uuid, UUID_LENGTH)) {
      break;
    }
  }

  if (device->busid != busid || device->devid != devid) {
    xd_log(LOG_ERR, "Device not found: %d", IN_dev_id);
    return FALSE;
  }
  if (strncmp(vm->uuid, IN_vm_uuid, UUID_LENGTH)) {
    xd_log(LOG_ERR, "VM not found: %s", IN_vm_uuid);
    return FALSE;
  }

  device->vm = vm;

  ret = usbowls_plug_device(vm->domid, device->busid, device->devid);
  if (ret != 0)
    return FALSE;

  return TRUE;
}

gboolean ctxusb_daemon_unassign_device(CtxusbDaemonObject *this,
                                       gint IN_dev_id, GError **error)
{
  struct list_head *pos;
  device_t *device;
  int busid, devid;
  int ret;

  makeBusDevPair(IN_dev_id, &busid, &devid);
  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      break;
    }
  }
  if (device->busid != busid || device->devid != devid) {
    xd_log(LOG_ERR, "Device not found: %d", IN_dev_id);
    return FALSE;
  }

  if (device->vm == NULL)
    return FALSE;
  ret = usbowls_unplug_device(device->vm->domid, device->busid, device->devid);
  if (ret != 0)
    return FALSE;

  device->vm = NULL;

  return TRUE;
}

gboolean ctxusb_daemon_set_sticky(CtxusbDaemonObject *this,
                                  gint IN_dev_id, gint IN_sticky, GError **error)
{
    return TRUE;
}

gboolean ctxusb_daemon_state(CtxusbDaemonObject *this,
                             char **OUT_state, GError **error)
{
    return TRUE;
}

gboolean ctxusb_daemon_name_device(CtxusbDaemonObject *this,
                                   gint IN_dev_id, const char* IN_name, GError **error)
{
    return TRUE;
}
