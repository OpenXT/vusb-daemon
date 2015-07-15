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

static int add_vm(int domid)
{
  char *uuid;

  uuid = xenstore_dom_read(domid, "vm");
  if (uuid == NULL) {
    xd_log(LOG_ERR, "Couldn't find UUID for domid %d", domid);
    return -1;
  }
  vm_add(domid, uuid + 4);
  free(uuid);

  return 0;
}

gboolean ctxusb_daemon_set_policy_domuuid(
    CtxusbDaemonObject *this,
    const char *uuid,
    const char *policy, GError **error)
{
  g_set_error(error,
	      DBUS_GERROR,
	      DBUS_GERROR_FAILED,
	      "set_policy_domuuid hasn't been implemented yet");

  return FALSE;
}

gboolean ctxusb_daemon_get_policy_domuuid(
    CtxusbDaemonObject *this,
    const char *uuid,
    char **value, GError **error)
{
  g_set_error(error,
	      DBUS_GERROR,
	      DBUS_GERROR_FAILED,
	      "get_policy_domuuid hasn't been implemented yet");

  return FALSE;
}

gboolean ctxusb_daemon_new_vm(CtxusbDaemonObject *this,
                              gint IN_dom_id, GError **error)
{
  int ret;

  ret = add_vm(IN_dom_id);

  if (ret) {
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"Failed to add VM %d", IN_dom_id);
    return FALSE;
  } else {
    return TRUE;
  }
}

gboolean ctxusb_daemon_vm_stopped(CtxusbDaemonObject *this,
                                  gint IN_dom_id, GError **error)
{
  int ret;

  ret = vm_del(IN_dom_id);

  if (ret) {
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"Failed to delete VM %d", IN_dom_id);
    return FALSE;
  } else {
    return TRUE;
  }
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

  makeBusDevPair(IN_dev_id, &busid, &devid);
  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      break;
    }
  }
  if (device->busid != busid || device->devid != devid) {
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"Device not found: %d", IN_dev_id);
    return FALSE;
  }
  *OUT_name = g_strdup(device->shortname);
  *OUT_state = 0;
  if (device->vm != NULL) {
    if (!strncmp(device->vm->uuid, IN_vm_uuid, UUID_LENGTH))
      *OUT_state = DEV_STATE_THIS;
    else
      *OUT_state = DEV_STATE_ASSIGNED;
    *OUT_vm_assigned = g_strdup(device->vm->uuid);
  } else {
    *OUT_state = DEV_STATE_UNUSED;
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
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"Device not found: %d", IN_dev_id);
    return FALSE;
  }
  if (strncmp(vm->uuid, IN_vm_uuid, UUID_LENGTH)) {
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"VM not found: %s", IN_vm_uuid);
    return FALSE;
  }
  if (vm->domid < 0) {
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"Can't assign device %d to stopped VM %s", IN_dev_id, IN_vm_uuid);
    return FALSE;
  }

  device->vm = vm;
  ret = usbowls_plug_device(vm->domid, device->busid, device->devid);
  if (ret != 0) {
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"Failed to plug device %d-%d to VM %d", device->busid, device->devid, vm->domid);
    device->vm = NULL;
    return FALSE;
  }

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
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"Device not found: %d", IN_dev_id);
    return FALSE;
  }

  if (device->vm == NULL) {
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"Device %d is not currently assigned to a VM, can't unassign", IN_dev_id);
    return FALSE;
  }
  ret = usbowls_unplug_device(device->vm->domid, device->busid, device->devid);
  if (ret != 0) {
    g_set_error(error,
		DBUS_GERROR,
		DBUS_GERROR_FAILED,
		"Failed to unplug device %d-%d from VM %d", device->busid, device->devid, device->vm->domid);
    return FALSE;
  }

  device->vm = NULL;

  return TRUE;
}

gboolean ctxusb_daemon_set_sticky(CtxusbDaemonObject *this,
                                  gint IN_dev_id, gint IN_sticky, GError **error)
{
  if (IN_sticky == 0)
    policy_unset_sticky(IN_dev_id);
  else
    policy_set_sticky(IN_dev_id);

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
