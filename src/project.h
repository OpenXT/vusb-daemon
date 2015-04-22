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
#include <libudev.h>
#include <usb.h>

#include "rpcgen/xenmgr_vm_client.h"
#include "rpcgen/xenmgr_client.h"
#include "list.h"
#include "classes.h"

#define UUID_LENGTH 37
#define DOM0_DOMID  0
#define DOM0_UUID   "00000000-0000-0000-0000-000000000000"
#define UIVM_UUID   "00000000-0000-0000-0000-000000000001"

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
  char *shortname;
  char *longname;
  vm_t *vm;
} device_t;

xcdbus_conn_t *g_xcbus;
vm_t vms;
device_t devices;

int usbowls_xenstore_init(void);
int usbowls_xenstore_deinit(void);
int usbowls_plug_device(int domid, int bus, int device);
int usbowls_unplug_device(int domid, int bus, int device);

void rpc_init(void);

#endif
