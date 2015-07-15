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

vm_t*
vm_lookup(const int domid)
{
  struct list_head *pos;
  vm_t *vm;

  list_for_each(pos, &vms.list) {
    vm = list_entry(pos, vm_t, list);
    if (vm->domid == domid) {
      return vm;
    }
  }

  return NULL;
}

vm_t*
vm_lookup_by_uuid(const char *uuid)
{
  struct list_head *pos;
  vm_t *vm;

  list_for_each(pos, &vms.list) {
    vm = list_entry(pos, vm_t, list);
    if (!strcmp(vm->uuid, uuid)) {
      break;
    }
  }

  if (!strcmp(vm->uuid, uuid))
    return vm;

  return NULL;
}

static char*
uuid_copy_and_sanitize(const char *uuid)
{
  char *res;
  int i;

  res = malloc(UUID_LENGTH);
  for (i = 0; i < UUID_LENGTH - 1; ++i)
    res[i] = (uuid[i] == '_') ? '-' : uuid[i];

  res[UUID_LENGTH - 1] = '\0';

  return res;
}

int
vm_add(const int domid, const char *uuid)
{
  struct list_head *pos;
  vm_t *vm;
  char *new_uuid;

  /* The UUID may have "_"s instead of "-"s, like in the xenmgr dbus reply.
     Fix this while duplicating the UUID. */
  new_uuid = uuid_copy_and_sanitize(uuid);

  list_for_each(pos, &vms.list) {
    vm = list_entry(pos, vm_t, list);
    if (vm->domid == domid) {
      xd_log(LOG_ERR, "new VM already registered: %d", domid);
      return -1;
    }
    if (!strcmp(vm->uuid, new_uuid)) {
      xd_log(LOG_WARN, "VM already registered: %s. Changing domid", new_uuid);
      vm->domid = domid;
      return 0;
    }
  }

  xd_log(LOG_INFO, "Adding vm, domid=%d, uuid=%s", domid, new_uuid);
  vm = malloc(sizeof(vm_t));
  vm->domid = domid;
  vm->uuid = new_uuid;
  list_add(&vm->list, &vms.list);

  return 0;
}

int
vm_del(const int domid)
{
  struct list_head *pos;
  vm_t *vm;

  list_for_each(pos, &vms.list) {
    vm = list_entry(pos, vm_t, list);
    if (vm->domid == domid) {
      break;
    }
  }
  if (vm->domid == domid) {
    xd_log(LOG_INFO, "Deleting vm, domid=%d, uuid=%s", vm->domid, vm->uuid);
    list_del(pos);
    free(vm->uuid);
    free(vm);
  } else {
    xd_log(LOG_ERR, "VM not found: %d", domid);
    return -1;
  }

  return 0;
}
