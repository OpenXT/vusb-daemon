/*
 * Copyright (c) 2014 Citrix Systems, Inc.
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
 * @file   rpc.c
 * @author Jed Lejosne <lejosnej@ainfosec.com>
 * @date   Thu Jul 30 13:22:55 2015
 *
 * @brief  DBus service
 *
 * Implementation of the dbus methods we expose
 */

#include "project.h"
#include "policy.h"

#define DEV_STATE_ERROR       -1 /**< Cannot find device */
#define DEV_STATE_UNUSED      0  /**< Device not in use by any VM */
#define DEV_STATE_ASSIGNED    1  /**< *ALWAYS* Assigned to another VM which is off */
#define DEV_STATE_IN_USE      2  /**< Assigned to another VM which is running */
#define DEV_STATE_BLOCKED     3  /**< Blocked by policy for this VM */
#define DEV_STATE_THIS        4  /**< In use by this VM */
#define DEV_STATE_THIS_ALWAYS 5  /**< In use by this VM and flagged "always" */
#define DEV_STATE_ALWAYS_ONLY 6  /**< Flagged as "always" assigned to this VM, but not currently in use */
#define DEV_STATE_PLATFORM    7  /**< Special platform device, listed purely for information */
#define DEV_STATE_HID_DOM0    8  /**< HiD device assigned to dom0 */
#define DEV_STATE_HID_ALWAYS  9  /**< HiD device currently assigned to dom0, but always assigned to another VM */
#define DEV_STATE_CD_DOM0     10 /**< External CD drive assigned to dom0 */
#define DEV_STATE_CD_ALWAYS   11 /**< External CD drive currently assigned to dom0, but always assigned to another VM */

#define SERVICE "com.citrix.xenclient.usbdaemon"
#define SERVICE_OBJ_PATH "/"

#define DBUS_RULE_STRUCT (dbus_g_type_get_struct ("GValueArray",\
      G_TYPE_INT,\
      G_TYPE_STRING,\
      G_TYPE_STRING,\
      G_TYPE_STRING,\
      G_TYPE_STRING,\
      G_TYPE_STRING,\
      DBUS_TYPE_G_STRING_STRING_HASHTABLE,\
      DBUS_TYPE_G_STRING_STRING_HASHTABLE,\
      G_TYPE_STRING,\
      G_TYPE_INVALID))

static DBusConnection  *g_dbus_conn = NULL;
static DBusGConnection *g_glib_dbus_conn = NULL;

/* CTXUSB_DAEMON dbus object implementation */
#include "rpcgen/ctxusb_daemon_server_obj.h"

static void free_hash_table(GHashTable* table)
{
  gpointer key, value;
  if (table == NULL) return;

  GHashTableIter iterator;
  g_hash_table_iter_init(&iterator, table);
  while (g_hash_table_iter_next (&iterator, &key, &value))
  {
    g_free(key);
    g_free(value);
  }
  g_hash_table_destroy(table);
}

/**
 * @brief Initialize the DBus RPC bits
 *
 * Grab the bus, initialize the xcdbus handle and export the server.
 */
void rpc_init(void)
{
  CtxusbDaemonObject *server_obj = NULL;

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
  /* Wait until all the services we talk to are up */
  xcdbus_wait_service(g_xcbus, "com.citrix.xenclient.input");
  xcdbus_wait_service(g_xcbus, "com.citrix.xenclient.xenmgr");
}

/**
 * @brief Helper to add a VM
 *
 * Reads the VM path from xenstore and call vm_add() on the UUID part.
 * We do this because VMs don't happen to have a "uuid" xenstore node...
 * Example:
 * @code
 * /local/domain/2/vm = "/vm/00000000-0000-0000-0000-000000000001"
 * @endcode
 * @param domid The VM domid
 *
 * @return A pointer to the new VM, or NULL if it failed
 */
static vm_t*
add_vm(int domid)
{
  char *uuid;
  vm_t *res;

  uuid = xenstore_dom_read(domid, "vm");
  if (uuid == NULL) {
    xd_log(LOG_ERR, "Couldn't find UUID for domid %d", domid);
    return NULL;
  }
  res = vm_add(domid, uuid + 4);
  free(uuid);

  return res;
}

gboolean ctxusb_daemon_new_vm(CtxusbDaemonObject *this,
                              gint IN_dom_id, GError **error)
{
  vm_t *vm;

  vm = add_vm(IN_dom_id);

  if (vm == NULL) {
    g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "Failed to add VM %d", IN_dom_id);
    return FALSE;
  } else {
    /* The VM was added correctly, let's run the sticky rules. If
     * anything goes wrong, this will return non-0, but the RPC
     * probably shouldn't fail... */
    policy_auto_assign_devices_to_new_vm(vm);
    return TRUE;
  }
}

gboolean ctxusb_daemon_policy_get_rule(CtxusbDaemonObject *this,
    gint IN_rule_id,
    char* *OUT_command,
    char* *OUT_description,
    char* *OUT_vendor_id,
    char* *OUT_device_id,
    char* *OUT_serial_number,
    GHashTable* *OUT_sysattrs,
    GHashTable* *OUT_udev_properties,
    char* *OUT_vm_uuid,
    GError** error)
{
  rule_t *rule = NULL;
  char **dict;

  GHashTable* rule_sysattrs = g_hash_table_new(g_str_hash, g_str_equal);
  GHashTable* rule_properties = g_hash_table_new(g_str_hash, g_str_equal);

  rule = policy_get_rule(IN_rule_id);

  if (rule == NULL) {
    g_set_error(error,
        DBUS_GERROR,
        DBUS_GERROR_FAILED,
        "Rule %d not found", IN_rule_id);
    return FALSE;
  }

  dict = rule->dev_sysattrs;
  if (dict != NULL)
  {
    while (*dict != NULL && *(dict + 1) != NULL)
    {
      g_hash_table_insert(rule_sysattrs,
          g_strdup(*dict),
          g_strdup(*(dict + 1)));
      dict += 2;
    }
  }

  dict = rule->dev_properties;
  if (dict != NULL)
  {
    while (*dict != NULL && *(dict + 1) != NULL)
    {
      g_hash_table_insert(rule_properties,
          g_strdup(*dict),
          g_strdup(*(dict + 1)));
      dict += 2;
    }
  }

  if (rule->dev_vendorid == 0x0)
    *OUT_vendor_id = g_strdup("");
  else
    *OUT_vendor_id = g_strdup_printf("%04X", rule->dev_vendorid);

  if (rule->dev_deviceid == 0x0)
    *OUT_device_id = g_strdup("");
  else
    *OUT_device_id = g_strdup_printf("%04X", rule->dev_deviceid);

  *OUT_command = policy_parse_command_enum(rule->cmd);
  *OUT_description = g_strdup(rule->desc);
  *OUT_serial_number = g_strdup(rule->dev_serial);
  *OUT_sysattrs = rule_sysattrs;
  *OUT_udev_properties = rule_properties;
  *OUT_vm_uuid = g_strdup(rule->vm_uuid);
  return TRUE;
}

gboolean ctxusb_daemon_policy_list(CtxusbDaemonObject *this,
    GArray* *OUT_rules,
    GError** error)
{
  uint16_t *rule_list = NULL;
  size_t size = 0;

  GArray *index_array = g_array_new(FALSE, TRUE, sizeof(gint));
  *OUT_rules = index_array;

  policy_list_rules(&rule_list, &size);

  for (size_t index=0; index < size; index++)
  {
    gint value = (gint)(rule_list[index]);
    g_array_append_val(index_array, value);
  }
  if (size != 0 && rule_list != NULL) free(rule_list);

  return TRUE;
}

gboolean ctxusb_daemon_policy_get_rules(CtxusbDaemonObject *this,
    GPtrArray* *OUT_rule_set,
    GError** error)
{
  uint16_t *rule_list = NULL;
  size_t size = 0;

  GPtrArray* response = g_ptr_array_new();
  *OUT_rule_set = response;

  policy_list_rules(&rule_list, &size);

  for (size_t index=0; index < size; index++)
  {
    gint pos = (gint)rule_list[index];
    char *command = NULL;
    char *description = NULL;
    char *vendor_id = NULL;
    char *device_id = NULL;
    char *serial_number = NULL;
    GHashTable *sysattrs;
    GHashTable *udev_properties;
    char* vm_uuid = NULL;

    if (! ctxusb_daemon_policy_get_rule(
        this,
        pos,
        &command,
        &description,
        &vendor_id,
        &device_id,
        &serial_number,
        &sysattrs,
        &udev_properties,
        &vm_uuid,
        error)) continue;

    GValue *value = g_new0(GValue, 1);
    g_value_init(value, DBUS_RULE_STRUCT);
    g_value_take_boxed(value,
        dbus_g_type_specialized_construct(DBUS_RULE_STRUCT));
    dbus_g_type_struct_set(value,
        0, pos,
        1, command,
        2, description,
        3, vendor_id,
        4, device_id,
        5, serial_number,
        6, sysattrs,
        7, udev_properties,
        8, vm_uuid,
        G_MAXUINT);
    g_ptr_array_add(response, g_value_get_boxed(value));

    g_free(command);
    g_free(description);
    g_free(vendor_id);
    g_free(device_id);
    g_free(serial_number);
    free_hash_table(sysattrs);
    free_hash_table(udev_properties);
    g_free(vm_uuid);

    g_free(value);
  }

  free(rule_list);
  return TRUE;
}

gboolean ctxusb_daemon_policy_remove_rule(CtxusbDaemonObject *this,
    gint IN_rule_id,
    GError **error)
{
  if (! policy_remove_rule(IN_rule_id))
  {
    g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "Failed to remove rule %d", IN_rule_id);
    return FALSE;
  }
  return TRUE;
}

gboolean ctxusb_daemon_policy_set_rule(CtxusbDaemonObject *this,
    gint IN_rule_id,
    const char *IN_command,
    const char *IN_description,
    const char *IN_vendor_id,
    const char *IN_device_id,
    const char *IN_serial_number,
    GHashTable *IN_sysattrs,
    GHashTable *IN_udev_properties,
    const char *IN_vm_uuid,
    GError* *error)
{
  rule_t *new_rule;
  guint sysattr_size = g_hash_table_size(IN_sysattrs);
  guint properties_size = g_hash_table_size(IN_udev_properties);
  GHashTableIter iterator;
  gpointer key, value;
  enum command cmd = policy_parse_command_string(IN_command);

  if (IN_rule_id < 0 || IN_rule_id > UINT16_MAX)
  {
    g_set_error(error,
        DBUS_GERROR,
        DBUS_GERROR_FAILED,
        "Invalid rule ID: %d", IN_rule_id);
    return FALSE;
  }

  if (cmd == UNKNOWN)
  {
    g_set_error(error,
        DBUS_GERROR,
        DBUS_GERROR_FAILED,
        "Invalid command: %s", IN_command);
    return FALSE;
  }

  /* Gets freed upon policy remove */
  new_rule = malloc(sizeof(rule_t));
  memset(new_rule, 0, sizeof(rule_t));

  new_rule->pos = IN_rule_id;
  new_rule->cmd = cmd;

  if (IN_vendor_id != NULL && IN_vendor_id[0] != '\0')
  {
    char *end = NULL;
    long value = strtol(IN_vendor_id, &end, 16);;
    if (end != NULL &&
        end == IN_vendor_id + strlen(IN_vendor_id) &&
        value >= 0 &&
        value <= UINT16_MAX)
    {
      new_rule->dev_vendorid = (uint16_t)value;
    }
    else
    {
      free(new_rule);
      g_set_error(error,
          DBUS_GERROR,
          DBUS_GERROR_FAILED,
          "Invalid vendor ID: %s", IN_vendor_id);
      return FALSE;
    }
  }

  if (IN_device_id != NULL && IN_device_id[0] != '\0')
  {
    char *end = NULL;
    long value = strtol(IN_device_id, &end, 16);
    if (end != NULL &&
        end == IN_device_id + strlen(IN_device_id) &&
        value >= 0 &&
        value <= UINT16_MAX)
    {
      new_rule->dev_deviceid = (uint16_t)value;
    }
    else
    {
      free(new_rule);
      g_set_error(error,
          DBUS_GERROR,
          DBUS_GERROR_FAILED,
          "Invalid vendor ID: %s", IN_device_id);
      return FALSE;
    }
  }

  if (IN_serial_number != NULL && IN_serial_number[0] != '\0')
  {
    new_rule->dev_serial = malloc(strlen(IN_serial_number) + 1);
    strcpy(new_rule->dev_serial, IN_serial_number);
  }

  if (IN_description != NULL && IN_description[0] != '\0')
  {
    new_rule->desc = malloc(strlen(IN_description) + 1);
    strcpy(new_rule->desc, IN_description);
  }

  if (IN_vm_uuid != NULL && IN_vm_uuid[0] != '\0')
  {
    new_rule->vm_uuid = malloc(strlen(IN_vm_uuid) + 1);
    strcpy(new_rule->vm_uuid, IN_vm_uuid);
  }

  if (sysattr_size > 0)
  {
    int index=0;
    new_rule->dev_sysattrs = calloc((2 * sysattr_size) + 1, sizeof(char*));
    g_hash_table_iter_init(&iterator, IN_sysattrs);
    while (g_hash_table_iter_next (&iterator, &key, &value))
    {
      new_rule->dev_sysattrs[index] = g_strdup(key);
      new_rule->dev_sysattrs[index + 1] = g_strdup(value);
      index += 2;
    }
  }

  if (properties_size > 0)
  {
    int index=0;
    new_rule->dev_properties = calloc((2 * properties_size) + 1, sizeof(char*));
    g_hash_table_iter_init(&iterator, IN_udev_properties);
    while (g_hash_table_iter_next (&iterator, &key, &value))
    {
      new_rule->dev_properties[index] = g_strdup(key);
      new_rule->dev_properties[index + 1] = g_strdup(value);
      index += 2;
    }
  }

  policy_add_rule(new_rule);
  return TRUE;
}

gboolean ctxusb_daemon_policy_set_rule_basic(CtxusbDaemonObject *this,
    gint IN_rule_id,
    const char *IN_command,
    const char *IN_description,
    const char *IN_vendor_id,
    const char *IN_device_id,
    const char *IN_serial_number,
    const char *IN_vm_uuid,
    GError **error)
{
  return ctxusb_daemon_policy_set_rule(this,
      IN_rule_id,
      IN_command,
      IN_description,
      IN_vendor_id,
      IN_device_id,
      IN_serial_number,
      g_hash_table_new(g_str_hash, g_str_equal),
      g_hash_table_new(g_str_hash, g_str_equal),
      IN_vm_uuid,
      error);
}

gboolean ctxusb_daemon_policy_set_rule_advanced(CtxusbDaemonObject *this,
    gint IN_rule_id,
    const char *IN_command,
    const char *IN_description,
    GHashTable *IN_sysattrs,
    GHashTable *IN_udev_properties,
    const char *IN_vm_uuid,
    GError **error)
{
  return ctxusb_daemon_policy_set_rule(this,
      IN_rule_id,
      IN_command,
      IN_description,
      "",
      "",
      "",
      IN_sysattrs,
      IN_udev_properties,
      IN_vm_uuid,
      error);
}

gboolean ctxusb_daemon_vm_stopped(CtxusbDaemonObject *this,
                                  gint IN_dom_id, GError **error)
{
  int ret;

  device_unplug_all_from_vm(IN_dom_id);

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
    id = device_make_id(device->busid, device->devid);
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
  device_t *device = NULL;
  int busid, devid;

  device_make_bus_dev_pair(IN_dev_id, &busid, &devid);
  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      break;
    }
  }
  if (device == NULL || device->busid != busid || device->devid != devid) {
    g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "Device not found: %d", IN_dev_id);
    return FALSE;
  }
  *OUT_name = g_strdup(device->shortname);
  /* Figure out the state and assigned VM for the device. Default to unused. */
  /* We could simply output the assigned VM and an always-assign
   * flag, but finding the right DEV_STATE is more fun, here goes... */
  if (device->vm != NULL) {
    /* The device is currently assigned to a VM */
    if (!strncmp(device->vm->uuid, IN_vm_uuid, UUID_LENGTH)) {
      /* The VM is IN_vm_uuid */
      char *uuid = policy_get_sticky_uuid(IN_dev_id);
      if (uuid != NULL && !strncmp(uuid, IN_vm_uuid, UUID_LENGTH))
        /* And it's always-assigned to it */
        *OUT_state = DEV_STATE_THIS_ALWAYS;
      else
        /* But it's not always-assigned to it */
        *OUT_state = DEV_STATE_THIS;
    } else
      /* The VM is not IN_vm_uuid */
      *OUT_state = DEV_STATE_IN_USE;
    /* Either way, the assigned VM is this */
    *OUT_vm_assigned = g_strdup(device->vm->uuid);
  } else {
    /* The device is not currently assigned to a VM */
    char *uuid = policy_get_sticky_uuid(IN_dev_id);
    if (uuid != NULL) {
      /* But it has an always-assign VM */
      if (device->type & OPTICAL)
        /* It's a CD drive */
        *OUT_state = DEV_STATE_CD_ALWAYS;
      else {
        if (!strncmp(uuid, IN_vm_uuid, UUID_LENGTH))
          /* Which is IN_vm_uuid */
          *OUT_state = DEV_STATE_ALWAYS_ONLY;
        else
          /* Or not */
          *OUT_state = DEV_STATE_ASSIGNED;
      }
      /* Either way, the assigned VM is this */
      *OUT_vm_assigned = g_strdup(uuid);
    } else {
      /* It doesn't have an always-assign VM, it's all free */
      if (device->type & OPTICAL)
        /* Unless it's a CD drive */
        *OUT_state = DEV_STATE_CD_DOM0;
      else
        *OUT_state = DEV_STATE_UNUSED;
      *OUT_vm_assigned = g_strdup("");
    }
  }
  *OUT_detail = g_strdup(device->longname);

  return TRUE;
}

gboolean ctxusb_daemon_assign_device(CtxusbDaemonObject *this,
                                     gint IN_dev_id, const char* IN_vm_uuid, GError **error)
{
  struct list_head *pos;
  device_t *device = NULL;
  vm_t *vm = NULL;
  char *sticky_uuid;
  int busid, devid;
  int ret;

  device_make_bus_dev_pair(IN_dev_id, &busid, &devid);
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

  if (device == NULL || device->busid != busid || device->devid != devid) {
    g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "Device not found: %d", IN_dev_id);
    return FALSE;
  }
  if (vm == NULL || strncmp(vm->uuid, IN_vm_uuid, UUID_LENGTH)) {
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
  if (device->vm != NULL) {
    g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "Device %d is already assigned to a VM", IN_dev_id);
    return FALSE;
  }
  sticky_uuid = policy_get_sticky_uuid(IN_dev_id);
  if (sticky_uuid != NULL && strcmp(vm->uuid, sticky_uuid)) {
    g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "Device %d is set to be always assigned to another VM", IN_dev_id);
    return FALSE;
  }
  if (!policy_is_allowed(device, vm, NULL)) {
    notify_com_citrix_xenclient_usbdaemon_device_rejected(g_xcbus,
							  USBDAEMON,
							  USBDAEMON_OBJ,
							  device->shortname,
							  "policy");
    g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "The policy denied assignment of device %d to VM %s", IN_dev_id, IN_vm_uuid);
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

  xd_log(LOG_INFO,
      "Device [Bus=%03d, Dev=%03d, VID=%04X, PID=%04X] plugged into VM [UUID=%s, DomID=%d]",
      device->busid,
      device->devid,
      device->vendorid,
      device->deviceid,
      vm->uuid,
      vm->domid);
  return TRUE;
}

gboolean ctxusb_daemon_unassign_device(CtxusbDaemonObject *this,
                                       gint IN_dev_id, GError **error)
{
  struct list_head *pos;
  device_t *device = NULL;
  int busid, devid;
  int res;
  gboolean ret = TRUE;

  device_make_bus_dev_pair(IN_dev_id, &busid, &devid);
  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      break;
    }
  }
  if (device == NULL || device->busid != busid || device->devid != devid) {
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
  res = usbowls_unplug_device(device->vm->domid, device->busid, device->devid);
  if (res != 0) {
    g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "Failed to gracefully unplug device %d-%d from VM %d", device->busid, device->devid, device->vm->domid);
    ret = FALSE;
  }
  xd_log(LOG_INFO,
      "Device [Bus=%03d, Dev=%03d, VID=%04X, PID=%04X, Serial=%s] unplugged from VM [UUID=%s, DomID=%d]",
      device->busid,
      device->devid,
      device->vendorid,
      device->deviceid,
      device->serial,
      device->vm->uuid,
      device->vm->domid);

  device->vm = NULL;

  return ret;
}

gboolean ctxusb_daemon_set_sticky(CtxusbDaemonObject *this,
                                  gint IN_dev_id, gint IN_sticky, GError **error)
{
  if (IN_sticky == 1 && false/* && policy_get_sticky_uuid(IN_dev_id) != NULL */) {
    g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "Device %d is set to be always assigned to a VM", IN_dev_id);
    return FALSE;
  }

  if (IN_sticky == 0)
    policy_unset_sticky(IN_dev_id);
  else {
    if (policy_set_sticky(IN_dev_id) == 1){
      g_set_error(error,
                DBUS_GERROR,
                DBUS_GERROR_FAILED,
                "Device %d is ambiguous, failed to set as sticky", IN_dev_id);
    return FALSE;
    }
  }

  return TRUE;
}

gboolean ctxusb_daemon_name_device(CtxusbDaemonObject *this,
                                   gint IN_dev_id, const char* IN_name, GError **error)
{
  return TRUE;
}

static int add_to_string(char **s, int len, const char *fmt, ...)
{
  int new_len;
  va_list ap;

  va_start(ap, fmt);
  new_len = len + vsnprintf(NULL, 0, fmt, ap) + 1;
  va_end(ap);

  *s = g_realloc(*s, new_len + 1);

  va_start(ap, fmt);
  vsprintf(*s + len, fmt, ap);
  va_end(ap);

  len = new_len;
  (*s)[len - 1] = '\n';
  (*s)[len] = '\0';

  return len;
}

gboolean ctxusb_daemon_state(CtxusbDaemonObject *this,
                             char **OUT_state, GError **error)
{
  int l = 0;
  struct list_head *pos;
  vm_t *vm;
  int vm_count = 0;
  device_t *device;
  int device_count = 0;

  l = add_to_string(OUT_state, l, "vusb-daemon state:");
  list_for_each(pos, &vms.list) {
    vm_count++;
  }
  l = add_to_string(OUT_state, l, "  VMs (%d):", vm_count);
  list_for_each(pos, &vms.list) {
    vm = list_entry(pos, vm_t, list);
    if (vm->domid >= 0)
      l = add_to_string(OUT_state, l, "    Running - %3d - %s", vm->domid, vm->uuid);
    else
      l = add_to_string(OUT_state, l, "    Stopped -     - %s", vm->uuid);
  }
  list_for_each(pos, &devices.list) {
    device_count++;
  }
  l = add_to_string(OUT_state, l, "  Devices (%d):", device_count);
  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    l = add_to_string(OUT_state, l, "    %s - %s", device->shortname, device->longname);
    l = add_to_string(OUT_state, l, "      ID: %d", device_make_id(device->busid, device->devid));
    l = add_to_string(OUT_state, l, "      Type: %d", device->type);
    l = add_to_string(OUT_state, l, "      Bus ID: %d, Device ID: %d", device->busid, device->devid);
    l = add_to_string(OUT_state, l, "      Vendor: 0x%04X, Device: 0x%04X", device->vendorid, device->deviceid);
    if (device->vm != NULL)
      l = add_to_string(OUT_state, l, "      Assigned to domid %d", device->vm->domid);
    else
      l = add_to_string(OUT_state, l, "      Not assigned to any VM");
  }
  /* Remove last \n */
  (*OUT_state)[l - 1] = '\0';

  return TRUE;
}

gboolean ctxusb_daemon_reload_policy(CtxusbDaemonObject *this, GError** error)
{
  policy_reload_from_db();

  return TRUE;
}
