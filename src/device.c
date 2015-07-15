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

device_t*
device_lookup(int busid, int devid)
{
  struct list_head *pos;
  device_t *device;

  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      return device;
    }
  }

  return NULL;
}

int
device_bind_to_dom0_by_sysname(const char *name)
{
  int fd;

  fd = open("/sys/bus/usb/drivers_probe", O_WRONLY);
  if (fd < 0)
    return -1;
  write(fd, name, strlen(name));
  close(fd);

  return 0;
}

int
device_bind_to_dom0(int busid, int devid)
{
  device_t *device;

  device = device_lookup(busid, devid);

  return device_bind_to_dom0_by_sysname(device->sysname);
}

/* Add a device to the global list of devices */
device_t*
device_add(int  busid,
	   int  devid,
	   int  vendorid,
	   int  deviceid,
	   char *shortname,
	   char *longname,
	   char *sysname)
{
  device_t *device;

  device = malloc(sizeof(device_t));

  device->busid = busid;
  device->devid = devid;
  device->vendorid = vendorid;
  device->deviceid = deviceid;
  device->shortname = shortname;
  device->longname = longname;
  device->sysname = sysname;
  device->vm = NULL; /* The UI isn't happy if the device is assigned to dom0 */
  list_add(&device->list, &devices.list);

  return device;
}

/* Remove a device from the global list of devices */
int
device_del(int  busid,
	   int  devid)
{
  struct list_head *pos;
  device_t *device;

  list_for_each(pos, &devices.list) {
    device = list_entry(pos, device_t, list);
    if (device->busid == busid && device->devid == devid) {
      break;
    }
  }
  if (device->busid == busid && device->devid == devid) {
    list_del(pos);
    free(device->shortname);
    free(device->longname);
    free(device->sysname);
    free(device);
  } else {
    xd_log(LOG_ERR, "Device not found: %d-%d", busid, devid);
    return -1;
  }

  return 0;
}

/* Build a string that represents the device type
   by finding the deepest known class/subclass/protocol.
   This uses the structure defined in classes.h, generated from usb.ids */
char*
device_type(unsigned char class,
	    unsigned char subclass,
	    unsigned char protocol)
{
  const class_t *tmp = classes;
  int n = 0;
  int m = 0;
  int size;
  char *res;

  /* Find the class */
  while (tmp->value != NULL && tmp->id != class)
    tmp++;
  if (tmp->value == NULL)
    return NULL;

  /* Find the subclass or return the class */
  while (tmp->subs != NULL && tmp->subs[n].value != NULL &&
	 tmp->subs[n].id != subclass)
    n++;
  if (tmp->subs == NULL || tmp->subs[n].value == NULL)
    {
      size = strlen(tmp->value) + 1;
      res = malloc(size);
      snprintf(res, size, "%s", tmp->value);
      return res;
    }

  /* Find the protocol or return the subclass */
  while (tmp->subs[n].prots != NULL && tmp->subs[n].prots[m].value != NULL &&
	 tmp->subs[n].prots[m].id != protocol)
    m++;
  if (tmp->subs[n].prots == NULL || tmp->subs[n].prots[m].value == NULL)
    {
      size = strlen(tmp->subs[n].value) + 1;
      res = malloc(size);
      snprintf(res, size, "%s", tmp->subs[n].value);
      return res;
    }

  /* Everything was found, returning the protocol */
  size = strlen(tmp->subs[n].prots[m].value) + 1;
  res = malloc(size);
  snprintf(res, size, "%s", tmp->subs[n].prots[m].value);

  return res;
}
