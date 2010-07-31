/*
 +----------------------------------------------------------------------+
 | PHP Version 5                                                        |
 +----------------------------------------------------------------------+
 | Copyright (c) 1997-2009												|
 +----------------------------------------------------------------------+
 | This source file is subject to version 3.01 of the PHP license,      |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.php.net/license/3_01.txt                                  |
 | If you did not receive a copy of the PHP license and are unable to   |
 | obtain it through the world-wide-web, please send a note to          |
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author: Andrew Colin Kissa <topdog@fedoraproject.org>                |
 +----------------------------------------------------------------------+
 */

/* $Id$ */ 

#ifndef PHP_COUCHDB_H
#define PHP_COUCHDB_H


extern zend_module_entry couchdb_module_entry;
#define phpext_couchdb_ptr &couchdb_module_entry

#define PHP_COUCHDB_NAME		"couchdb"
#define PHP_COUCHDB_VERSION		"0.0.2"
#define COUCHDB_CLASS			"CouchdbClient"
#define COUCHDB_EXCEPTION_CLASS "CouchdbClientException"

#define TC_ME(func, arg_info, flags) PHP_ME(CouchdbClient, func, arg_info, flags)
#define TC_MALIAS(func, alias, arg_info, flags) PHP_MALIAS(CouchdbClient, func, alias, arg_info, flags)
#define TC_METHOD(func) PHP_METHOD(CouchdbClient, func)

#define COUCHDB_LAST_RAW_RES			"couchdb_last_raw_res"
#define COUCHDB_URL						"couchdb_url"
#define COUCHDB_DB						"couchdb_db"
#define COUCHDB_USER					"couchdb_user"
#define COUCHDB_PASSWORD				"couchdb_password"
#define COUCHDB_POST					"POST"
#define COUCHDB_GET						"GET"
#define COUCHDB_PUT						"PUT"
#define COUCHDB_DELETE					"DELETE"
#define COUCHDB_COPY					"COPY"
#define COUCHDB_CHANGES					"/_changes"
#define COUCHDB_CONFIG					"/_config"
#define COUCHDB_STATS					"/_stats"
#define COUCHDB_SESSION					"/_session"
#define COUCHDB_ACTIVE_TASK				"/_active_tasks"
#define COUCHDB_ALL_DOCS				"/_all_docs"
#define COUCHDB_ALL_DOCS_SEQ			"/_all_docs_by_seq"
#define COUCHDB_ALL_DBS					"/_all_dbs"
#define COUCHDB_BULK_DOCS				"/_bulk_docs"
#define COUCHDB_TEMP_VIEW				"/_temp_view"
#define COUCHDB_GET_UUIDS				"/_uuids"
#define COUCHDB_COMPACT					"/_compact"
#define COUCHDB_REPLICATE				"/_replicate"
#define COUCHDB_CA_PATH					"couchdb_ca_path"
#define COUCHDB_CA_INFO					"couchdb_ca_info"
#define COUCHDB_ACCEPT_HEADERS			"Accept: application/json,text/html,text/plain,*/*"
#define COUCHDB_STATUS_OK				200
#define COUCHDB_STATUS_CREATED			201
#define COUCHDB_STATUS_ACCEPTED			202
#define COUCHDB_STATUS_NOTMOD			304
#define COUCHDB_STATUS_NOTFOUND			404
#define COUCHDB_STATUS_CONFLICT			409
#define COUCHDB_STATUS_IERROR			500
#define COUCHDB_STATUS_END				206
#define COUCHDB_MAX_HEADER_LEN			512L

#define COUCHDB_DB_NONE					0
#define COUCHDB_DB_INFO					1
#define COUCHDB_DB_COMPACT				2
#define COUCHDB_DB_DELETE				3

#define COUCHDB_EMPTY_PARAMS			"Method parameters can not be empty strings"
#define COUCHDB_COOKIE_PARAMS			"user_name and password must be supplied for cookie based authentication"
#define COUCHDB_COOKIE_AUTH_FAILURE		"Cookie authentication failed"
#define COUCHDB_DOC_PARAM_TYPE			"Expects parameter 1 to be a JSON encoded string, array or stdClass object"
#define COUCHDB_INVALID_JSON_STRING		"The string paramter supplied is not valid JSON"
#define COUCHDB_JSON_ENCODE_FAIL		"JSON encoding failed"
#define COUCHDB_JSON_ENCODE_NULL		"JSON encoding returned a null value"
#define COUCHDB_JSON_INVALID			"The JSON is invalid"
#define COUCHDB_FILE_OPEN_FAIL			"The file %s could not be opened"
#define COUCHDB_FILE_EMPTY				"The file %s is empty"
#define COUCHDB_FILE_READ_FAIL			"The file %s could not be read"
#define COUCHDB_DB_DESELECT_FAIL		"Unselecting of the database failed"
#define COUCHDB_INVALID_URI				"The uri parameter is invalid"
#define COUCHDB_INVALID_SCHEME			"The url scheme %s you supplied is not supported"
#define COUCHDB_COOKIE_NOT_GOT			"Server did not send any cookie"
#define COUCHDB_SERVER_FAIL				"HTTP request failed with Error message: %s"
#define COUCHDB_DB_NOT_SET				"The database name has not been set, use selectDB() to set the database name"

#endif /* PHP_COUCHDB_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
