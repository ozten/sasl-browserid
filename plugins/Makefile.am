AM_CFLAGS = -I/usr/include/sasl -lyajl `mysql_config --include --libs` -lcurl
AM_LDFLAGS = -module -export-dynamic -rpath @plugindir@
lib_LTLIBRARIES = libbrowserid.la
libbrowserid_la_SOURCES = browserid.c browserid_init.c verifier.h verifier.c session.c session.h
libbrowserid_la_LDFLAGS = -rpath $(libdir)
libdir = @plugindir@