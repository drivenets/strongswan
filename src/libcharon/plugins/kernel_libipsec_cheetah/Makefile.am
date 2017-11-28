AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libipsec

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-kernel-libipsec-cheetah.la
else
plugin_LTLIBRARIES = libstrongswan-kernel-libipsec-cheetah.la
endif

libstrongswan_kernel_libipsec_cheetah_la_SOURCES = \
	kernel_libipsec_cheetah_plugin.h kernel_libipsec_cheetah_plugin.c \
	kernel_libipsec_cheetah_ipsec.h kernel_libipsec_cheetah_ipsec.c \
	kernel_libipsec_cheetah_router.h kernel_libipsec_cheetah_router.c \
	nano_server.h nano_server.c \
	qpb.pb-c.h qpb.pb-c.c \
	ipsec.pb-c.h ipsec.pb-c.c \
	nanomsg_transport.pb-c.h nanomsg_transport.pb-c.c \
	neighbor_provision.pb-c.h neighbor_provision.pb-c.c \
	fpm.pb-c.h fpm.pb-c.c \
	nanoserver.pb-c.h nanoserver.pb-c.c 

libstrongswan_kernel_libipsec_cheetah_la_LIBADD = $(top_builddir)/src/libipsec/libipsec.la

libstrongswan_kernel_libipsec_cheetah_la_LDFLAGS = -module -avoid-version -lnanomsg -lprotobuf-c
