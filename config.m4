dnl config.m4 for couchdb
dnl $Id: $
dnl vim: noet ts=1 sw=1

PHP_ARG_ENABLE([couchdb], [whether to enable couchdb support],
[  --enable-couchdb       Enable couchdb support])

if test "$PHP_COUCHDB" != "no"; then
	PHP_SUBST(COUCHDB_SHARED_LIBADD)

	PHP_ADD_LIBRARY(curl,,COUCHDB_SHARED_LIBADD) 

	PHP_NEW_EXTENSION(couchdb, couchdb.c, $ext_shared)
	CFLAGS="$CFLAGS -Wall -g"

	PHP_ADD_EXTENSION_DEP(couchdb, curl)
	PHP_ADD_EXTENSION_DEP(couchdb, json)
fi 
