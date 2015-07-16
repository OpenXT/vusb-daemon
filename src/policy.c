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

#define STICKY_FILE_PATH "/config/etc/USB_always.conf"

typedef struct {
  struct list_head list;
  int vendorid;
  int deviceid;
  char *serial;
  char *uuid;
} sticky_t;

static bool auto_assign_to_focused_vm = true;

sticky_t stickys;

static int
policy_dump_stickys_to_file(void)
{
  FILE *file;
  char line[1024];
  int ret;
  struct list_head *pos;

  file = fopen(STICKY_FILE_PATH, "w");
  if (file == NULL)
    {
      xd_log(LOG_WARN, "No USB sticky loaded as the file couldn't be opened");
      return -1;
    }
  list_for_each(pos, &stickys.list)
    {
      sticky_t *sticky;

      sticky = list_entry(pos, sticky_t, list);
      snprintf(line, 1024, "%X:%X:\"%s\"=\"%s\"\n",
	       sticky->vendorid, sticky->deviceid, sticky->serial, sticky->uuid);
      fputs(line, file);
    }
  fclose(file);
}

static void
sticky_add_noalloc(int vendorid,
		    int deviceid,
		    char *serial,
		    char *uuid)
{
  sticky_t *sticky;

  sticky = malloc(sizeof(sticky_t));
  sticky->vendorid = vendorid;
  sticky->deviceid = deviceid;
  sticky->serial = serial;
  sticky->uuid = uuid;
  list_add(&sticky->list, &stickys.list);
}

static void
sticky_add(int vendorid,
	   int deviceid,
	   const char *serial,
	   const char *uuid)
{
  char *newserial, *newuuid;

  newserial = malloc(strlen(serial) + 1);
  strcpy(newserial, serial);
  newuuid = malloc(strlen(uuid) + 1);
  strcpy(newuuid, uuid);
  sticky_add_noalloc(vendorid, deviceid, newserial, newuuid);
}

static sticky_t*
sticky_lookup(int vendorid,
	      int deviceid,
	      const char *serial)
{
  struct list_head *pos;
  sticky_t *sticky;

  list_for_each(pos, &stickys.list) {
    sticky = list_entry(pos, sticky_t, list);
    /* Check for a match. Ignore any trailing info in the serial. */
    if (sticky->vendorid == vendorid &&
	sticky->deviceid == deviceid &&
	!strncmp(sticky->serial, serial, strlen(serial))) {
      return sticky;
    }
  }

  return NULL;
}

static int
sticky_del(int vendorid,
	   int deviceid,
	   const char *serial)
{
  sticky_t *sticky;

  sticky = sticky_lookup(vendorid, deviceid, serial);
  if (sticky == NULL)
    return -1;
  list_del(&sticky->list);
  free(sticky->serial);
  free(sticky->uuid);
  free(sticky);

  return 0;
}

static int
policy_read_stickys_from_file(void)
{
  FILE *file;
  char line[1024];
  int ret;

  file = fopen(STICKY_FILE_PATH, "r");
  if (file == NULL)
    {
      xd_log(LOG_WARN, "No USB sticky loaded as the file couldn't be opened");
      return 0;
    }
  while (fgets(line, 1024, file) != NULL)
    {
      char *begin = line;
      char *end;
      int size;
      int vendorid, deviceid;
      char *serial, *uuid;

      /* Default to failure if we break */
      ret = -2;

      /* Read the vendorid and make sure it's followed by ':' */
      vendorid = strtol(begin, &end, 16);
      if (end == NULL || *end != ':')
	break;
      begin = end + 1;

      /* Read the deviceid and make sure it's followed by ':' and '"' */
      deviceid = strtol(begin, &end, 16);
      if (end == NULL || *end != ':' || *(end + 1) != '"')
	break;
      begin = end + 2;

      /* Read the serial and make sure it's followed by '"', '=', and '"' */
      end = strchr(begin, '"');
      if (end == NULL)
	break;
      size = end - begin;
      serial = malloc(size + 1);
      strncpy(serial, begin, size);
      serial[size] = '\0';
      if (end == NULL || *end != '"' || *(end + 1) != '=' || *(end + 2) != '"')
	break;
      begin = end + 3;

      /* Read the uuid and make sure it's UUID_LENGTH, and followed by '"'.
         The end of the line will be discarded */
      end = strchr(begin, '"');
      if (end == NULL)
	break;
      size = end - begin;
      if (size != UUID_LENGTH - 1)
	break;
      uuid = malloc(size + 1);
      strncpy(uuid, begin, size);
      uuid[size] = '\0';
      if (end == NULL || *end != '"')
	break;

      /* All set. Create the rule item and set ret to success (0) */
      sticky_add_noalloc(vendorid, deviceid, serial, uuid);
      ret = 0;
    }

  if (ret == -2)
    xd_log(LOG_ERR, "Error while reading the USB sticky file");
  fclose(file);

  return ret;
}

int
policy_set_sticky(int dev)
{
  int busid, devid;
  device_t *device;

  makeBusDevPair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL || device->vm == NULL)
    return -1;
  sticky_add(device->vendorid, device->deviceid, device->shortname, device->vm->uuid);
  policy_dump_stickys_to_file();
}

int
policy_unset_sticky(int dev)
{
  int busid, devid;
  device_t *device;

  makeBusDevPair(dev, &busid, &devid);
  device = device_lookup(busid, devid);
  if (device == NULL || device->vm == NULL)
    return -1;
  return sticky_del(device->vendorid, device->deviceid, device->shortname);
}

static vm_t*
vm_focused(void)
{
  int domid;

  xcdbus_input_get_focus_domid(g_xcbus, &domid);

  return vm_lookup(domid);
}

int
policy_auto_assign(device_t *device)
{
  sticky_t *sticky;
  vm_t *vm = NULL;
  int uivm;

  sticky = sticky_lookup(device->vendorid, device->deviceid, device->shortname);
  if (sticky != NULL)
    vm = vm_lookup_by_uuid(sticky->uuid);
  if (vm == NULL && auto_assign_to_focused_vm)
    vm = vm_focused();

  property_get_com_citrix_xenclient_xenmgr_vm_domid_(g_xcbus, XENMGR, UIVM_PATH, &uivm);
  if (vm != NULL && vm->domid != 0 && vm->domid != uivm)
    {
      int res;

      device->vm = vm;
      res = usbowls_plug_device(vm->domid, device->busid, device->devid);
      if (res != 0)
	device->vm = NULL;
      return res;
    }

  return -1;
}

int
policy_init(void)
{
  INIT_LIST_HEAD(&stickys.list);

  return policy_read_stickys_from_file();
}
