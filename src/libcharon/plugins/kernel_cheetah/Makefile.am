AM_CPPFLAGS = \
	-I${linux_headers} \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-cheetah.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-cheetah.la
endif

libstrongswan_kernel_cheetah_la_SOURCES = \
	kernel_cheetah_plugin.h kernel_cheetah_plugin.c \
	kernel_netlink_ipsec.h kernel_netlink_ipsec.c \
	kernel_netlink_net.h kernel_netlink_net.c \
	kernel_netlink_shared.h kernel_netlink_shared.c \
	nano_server.h nano_server.c \
	qpb.pb-c.h qpb.pb-c.c \
	ipsec.pb-c.h ipsec.pb-c.c \
	nanomsg_transport.pb-c.h nanomsg_transport.pb-c.c \
	neighbor_provision.pb-c.h neighbor_provision.pb-c.c \
	fpm.pb-c.h fpm.pb-c.c \
	nanoserver.pb-c.h nanoserver.pb-c.c 

libstrongswan_kernel_cheetah_la_LDFLAGS = -module -avoid-version -lnanomsg -lprotobuf-c
