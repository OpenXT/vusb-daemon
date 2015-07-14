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

#define ALWAYS_FILE_PATH "/config/etc/USB_always.conf"

typedef struct {
  struct list_head list;
  int vendorid;
  int deviceid;
  char *serial;
  char *uuid;
} always_t;

static bool auto_assign_to_focused_vm = false;

always_t alwayss;

/* Caller is responsible for allocating the strings. always_del() will free them */
static void
always_add(int vendorid,
	   int deviceid,
	   char *serial,
	   char *uuid)
{
  always_t *always;

  always = malloc(sizeof(always_t));
  always->vendorid = vendorid;
  always->deviceid = deviceid;
  /* always->serial = malloc(strlen(serial)); */
  /* strcpy(always->serial, serial); */
  /* always->uuid = malloc(strlen(uuid)); */
  /* strcpy(always->uuid, uuid); */
  always->serial = serial;
  always->uuid = uuid;
  list_add(&always->list, &alwayss.list);
}

static int
policy_read_always_from_file(void)
{
  FILE *file;
  char line[1024];
  int ret;

  file = fopen(ALWAYS_FILE_PATH, "r");
  if (file == NULL)
    {
      xd_log(LOG_WARN, "No USB always loaded as the file couldn't be opened");
      return 1;
    }
  while (fgets(line, 1024, file) != NULL)
    {
      char *begin = line;
      char *end;
      int size;
      int vendorid, deviceid;
      char *serial, *uuid;

      /* Default to failure if we break */
      ret = 2;

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
      if (end == NULL || *end != '"' || *(end + 1) != '\0')
	break;

      /* All set. Create the rule item and set ret to success (0) */
      always_add(vendorid, deviceid, serial, uuid);
      ret = 0;
    }

  if (ret == 2)
    xd_log(LOG_ERR, "Error while reading the USB always file");
  fclose(file);

  return ret;
}

static int
policy_dump_always_to_file(void)
{
  FILE *file;
  char line[1024];
  int ret;
  struct list_head *pos;

  file = fopen(ALWAYS_FILE_PATH, "w");
  if (file == NULL)
    {
      xd_log(LOG_WARN, "No USB always loaded as the file couldn't be opened");
      return 1;
    }
  list_for_each(pos, &alwayss.list)
    {
      always_t *always;

      always = list_entry(pos, always_t, list);
      snprintf(line, 1024, "%X:%X:\"%s\"=\"%s\"\n",
	       always->vendorid, always->deviceid, always->serial, always->uuid);
      fputs(line, file);
    }
  fclose(file);
}

void
policy_add_always(int vendorid,
		  int deviceid,
		  const char *serial,
		  const char *uuid)
{
  char *new_serial, *new_uuid;

  new_serial = malloc(strlen(serial));
  strcpy(new_serial, serial);
  new_uuid = malloc(strlen(uuid));
  strcpy(new_uuid, uuid);
  always_add(vendorid, deviceid, new_serial, new_uuid);
  policy_dump_always_to_file();
}

always_t*
policy_find_always(int bus, int device)
{
  return NULL;
}

vm_t*
vm_focused(void)
{
  return NULL;
}

void
policy_init()
{
  INIT_LIST_HEAD(&alwayss.list);
}

vm_t*
policy_auto_assign(int bus, int device)
{
  always_t *always;
  vm_t *vm;

  always = policy_find_always(bus, device);
  if (always != NULL)
    return vm_lookup_by_uuid(always->uuid);
  if (auto_assign_to_focused_vm)
    {
      vm = vm_focused();
      if (vm != NULL && vm->domid != 0)
	return vm;
    }

  return NULL;
}
