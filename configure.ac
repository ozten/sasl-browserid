#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([sasl_browserid], [0.0.1], [shout@ozten.com])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([plugins/browserid.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
# TODO sasl doesn't work
# TODO LIB peices don't affect make command... 
AC_CHECK_LIB(sasl, SASL_OK, [CFLAG="$CFLAG -I/usr/include/sasl"])
AC_CHECK_LIB(mysqlclient, mysql_init, [MYSQLLIB=`mysql_config --include --libs`])
AC_CHECK_LIB(yajl, yajl_parse, [YAJLLIB=-lyajl])

# Checks for header files.
AC_CHECK_HEADERS([config.h arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h syslog.h unistd.h sasl/sasl.h])

AC_CONFIG_FILES([Makefile plugins/Makefile])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strcasecmp strchr strerror strndup uname])

AC_ARG_WITH(plugindir, [ --with-plugindir=DIR     set the directory where plugins will
                       be found [[/usr/lib/sasl2]] ],
                       plugindir=$withval,
                       plugindir=/usr/lib/sasl2)

AC_DEFINE_UNQUOTED(PLUGINDIR, "$plugindir", [Runtime plugin location])
AC_SUBST(plugindir)

AC_OUTPUT
