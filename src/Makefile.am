#
# Copyright (c) 2015 Jed Lejosne <lejosnej@ainfosec.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

DBUS_CLIENT_IDLS = xenmgr xenmgr_vm
DBUS_SERVER_IDLS = ctxusb_daemon

AM_CFLAGS = -finput-charset=UTF-8 -std=gnu99 -DROOT_UID=0 -DHAVE_ARCH_STRUCT_FLOCK -DUSE_DBUS -DHAVE_ARCH_STRUCT_FLOCK

INCLUDES = @DBUS_CFLAGS@ @DBUS_GLIB_CFLAGS@ @LIBXCDBUS_INC@ @LIBV4V_INC@ @LIBUSB_CFLAGS@ @LIBXCXENSTORE_CFLAGS@ @LIBEXPAT_INC@ @UDEV_CFLAGS@

sbin_PROGRAMS = vusb-daemon

PROTO_SRCS = main.c usbowls.c rpc.c udev.c device.c vm.c

vusb_daemon_SOURCES = ${PROTO_SRCS} rpcgen/ctxusb_daemon_server_obj.c

# Add -lusb-1.0 for a decent usb lib
vusb_daemon_LDADD = @LIBXCXENSTORE_LIBS@ @LIBEXPAT_LIB@ @DBUS_LIBS@ @DBUS_GLIB_LIBS@ @LIBXCDBUS_LIBS@ @UDEV_LIBS@ -lusb -levent

BUILT_SOURCES = \
        ${DBUS_CLIENT_IDLS:%=rpcgen/%_client.h} \
        ${DBUS_SERVER_IDLS:%=rpcgen/%_server_marshall.h} \
        ${DBUS_SERVER_IDLS:%=rpcgen/%_server_obj.c} \
        ${DBUS_SERVER_IDLS:%=rpcgen/%_server_obj.h}


rpcgen/%_client.h: ${IDLDIR}/%.xml
	mkdir rpcgen || true
	${XC_RPCGEN} -c -o rpcgen/ $<

rpcgen/%_server_marshall.h rpcgen/%_server_obj.h rpcgen/%_server_obj.c : ${IDLDIR}/%.xml
	mkdir rpcgen || true
	${XC_RPCGEN} -s -o rpcgen/ $<

protos: ${BUILD_SOURCES}
	echo > prototypes.h
	cproto -E "${CPP} ${CPPFLAGS}" ${INCLUDES} -I. -DPROTOS -v -e ${PROTO_SRCS} > prototypes.tmp
	mv prototypes.tmp prototypes.h

