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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_smart_str.h"
#include "ext/standard/url.h"
#include "Zend/zend_extensions.h"
#include "php_couchdb.h"
#include "ext/json/php_json.h"

#include <curl/curl.h>


#define CAAL(s, v) add_assoc_long_ex(returned_info, s, sizeof(s), (long) v);
#define CAAD(s, v) add_assoc_double_ex(returned_info, s, sizeof(s), (double) v);
#define CAAS(s, v) add_assoc_string_ex(returned_info, s, sizeof(s), (char *) (v ? v : ""), 1);


#define COUCHDB_ERROR(errcode, msg, ... ) \
	zend_throw_exception_ex(couchdb_exception_ce_ptr, errcode TSRMLS_CC, msg, ##__VA_ARGS__);

#define FREE_ARGS_HASH(a) \
		if (a) { \
			zend_hash_destroy(a); \
			FREE_HASHTABLE(a); \
		} 

#define PROCESS_JSON_RESULT(code, object, assoc) \
	if (code != -1 && object->lastresponse.c) { \
		MAKE_STD_ZVAL(zret); \
		ZVAL_STRINGL(zret, object->lastresponse.c, object->lastresponse.len, 1); \
		couchdb_set_response_args(object->properties, zret TSRMLS_CC); \
		php_json_decode(return_value, object->lastresponse.c, object->lastresponse.len, assoc TSRMLS_CC); \
		return; \
	}else{ \
		RETURN_NULL(); \
	} \

#define PROCESS_JSON_RESULT_EX(code, object, assoc) \
	if (code != -1 && object->lastresponse.c) { \
		MAKE_STD_ZVAL(zret); \
		ZVAL_STRINGL(zret, object->lastresponse.c, object->lastresponse.len, 1); \
		couchdb_set_response_args(object->properties, zret TSRMLS_CC); \
		php_json_decode(return_value, object->lastresponse.c, object->lastresponse.len, assoc TSRMLS_CC); \
		return; \
	}else{ \
		COUCHDB_ERROR(0, object->lastresponse.c); \
	} \

#define PROCESS_JSON_RESULT_COMPART(code, object, assoc) \
	long depth = JSON_PARSER_DEFAULT_DEPTH; \
	if (code != -1 && object->lastresponse.c) { \
		MAKE_STD_ZVAL(zret); \
		ZVAL_STRINGL(zret, object->lastresponse.c, object->lastresponse.len, 1); \
		couchdb_set_response_args(object->properties, zret TSRMLS_CC); \
		php_json_decode(return_value, object->lastresponse.c, object->lastresponse.len, assoc, depth TSRMLS_CC); \
		return; \
	}else{ \
		RETURN_NULL(); \
	} \

#define PROCESS_JSON_RESULT_COMPART_EX(code, object, assoc) \
	long depth = JSON_PARSER_DEFAULT_DEPTH; \
	if (code != -1 && object->lastresponse.c) { \
		MAKE_STD_ZVAL(zret); \
		ZVAL_STRINGL(zret, object->lastresponse.c, object->lastresponse.len, 1); \
		couchdb_set_response_args(object->properties, zret TSRMLS_CC); \
		php_json_decode(return_value, object->lastresponse.c, object->lastresponse.len, assoc, depth TSRMLS_CC); \
		return; \
	}else{ \
		if (object->lastresponse.len) { \
			COUCHDB_ERROR(0, object->lastresponse.c); \
		}else{ \
			COUCHDB_ERROR(0, "Unknown error"); \
		} \
	} \

#define PROCESS_BOOL_RESULT(code, object, rcode) \
	if (code == rcode && object->lastresponse.c) { \
		MAKE_STD_ZVAL(zret); \
		ZVAL_STRINGL(zret, object->lastresponse.c, object->lastresponse.len, 1); \
		couchdb_set_response_args(object->properties, zret TSRMLS_CC); \
		RETURN_TRUE; \
	}else{ \
		RETURN_FALSE; \
	} \

#define PROCESS_BOOL_RESULT_EX(code, object, rcode) \
	if (code == rcode && object->lastresponse.c) { \
		MAKE_STD_ZVAL(zret); \
		ZVAL_STRINGL(zret, object->lastresponse.c, object->lastresponse.len, 1); \
		couchdb_set_response_args(object->properties, zret TSRMLS_CC); \
		RETURN_TRUE; \
	}else{ \
		if (object->lastresponse.len) { \
			COUCHDB_ERROR(0, object->lastresponse.c); \
		}else { \
			COUCHDB_ERROR(0, "Unknown error"); \
		}\
	} \

#define CHECK_DB_NAME(object) \
	db_name_len = Z_STRLEN_PP(couchdb_get_property(object, COUCHDB_DB TSRMLS_CC)); \
	if (!db_name_len) { \
		COUCHDB_ERROR(0, COUCHDB_DB_NOT_SET); \
		return; \
	} \
	db_name = Z_STRVAL_PP(couchdb_get_property(object, COUCHDB_DB TSRMLS_CC)); \


#ifndef TRUE
	#define TRUE 1
	#define FALSE 0
#endif

#ifndef MIN
#   define MIN(a,b) (a<b?a:b)
#endif

#ifndef JSON_PARSER_DEFAULT_DEPTH
	#define JSON_PARSER_DEFAULT_DEPTH 512
#endif

static zend_object_handlers couchdb_client_handlers;

static zend_class_entry *couchdb_client_ce_ptr = NULL;
static zend_class_entry *couchdb_exception_ce_ptr = NULL;


typedef struct _php_couchdb_object {
	zend_object std;
	HashTable *properties;
	void ***thread_ctx;
	smart_str lastresponse;
	smart_str lastrequest;
	smart_str cookie;
	zend_bool use_cookie_auth;
	uint previous:28;
	zval *this_ptr;
} php_couchdb_object;

static int couchdb_add_req_arg(HashTable *ht, const char *arg, const char *val TSRMLS_DC) /* {{{ */
{
	zval *varg;
	ulong h;
	
	MAKE_STD_ZVAL(varg);
	ZVAL_STRING(varg, (char *)val, 1);
	
	h = zend_hash_func((char *)arg, strlen(arg)+1);
	zend_hash_quick_update(ht, (char *)arg, strlen(arg)+1, h, &varg, sizeof(zval *), NULL);
	
	return SUCCESS;
}
/* }}} */

static char *couchdb_encode_url(char *url) /* {{{ */
{
	char *encoded_url = NULL, *rets;
	int encoded_url_len, rets_len;
	
	if (url) {
		encoded_url = php_raw_url_encode(url, strlen(url), &encoded_url_len);
	}
	
	if (encoded_url) {
		rets = php_str_to_str_ex(encoded_url, encoded_url_len, "%7E", sizeof("%7E")-1, "~", sizeof("~")-1, &rets_len, 0, NULL);
		efree(encoded_url);
		return rets;
	}
	
	return NULL;
}
/* }}} */

int couchdb_build_query(smart_str *s, HashTable *args, zend_bool prepend_amp) /* {{{ */
{
	HashPosition pos;
	void *current_val;
	char *arg_key = NULL, *current_key = NULL, *param_value;
	int numargs = 0;
	ulong idx = 0;
	
	if (args) {
		for (zend_hash_internal_pointer_reset_ex(args, &pos); zend_hash_get_current_key_ex(args, &current_key, 0, &idx, 0, &pos) != HASH_KEY_NON_EXISTANT;
			 zend_hash_move_forward_ex(args, &pos)) {
			if (current_key) {
				if (prepend_amp) {
					smart_str_appendc(s, '&');
				}
				zend_hash_get_current_data_ex(args, (void **)&current_val, &pos);
				arg_key = couchdb_encode_url(current_key);
				
				if (Z_TYPE_PP((zval **)current_val) == IS_STRING) {
					param_value = couchdb_encode_url(Z_STRVAL_PP((zval **)current_val));
				}else {
					SEPARATE_ZVAL((zval **)current_val);
					convert_to_string_ex((zval **)current_val);
					param_value = couchdb_encode_url(Z_STRVAL_PP((zval **)current_val));
				}

				
				if (arg_key && param_value) {
					smart_str_appends(s, arg_key);
					efree(arg_key);
				}else {
					efree(arg_key);
				}

				
				if (param_value) {
					smart_str_appendc(s, '=');
					smart_str_appends(s, param_value);
					efree(param_value);
				}
				
				prepend_amp = TRUE;
				++numargs;
			}
		}
	}
	
	return numargs;
}
/* }}} */

static smart_str *http_url_concat(smart_str *surl) /* {{{ */
{
	smart_str_0(surl);
	if (!strchr(surl->c, '?')) {
		smart_str_appendc(surl, '?');
	}else {
		smart_str_appendc(surl, '&');
	}
	
	return surl;
}
/* }}} */

static int couchdb_set_response_args(HashTable *hasht, zval *data TSRMLS_DC) /* {{{ */
{
	if (data && Z_TYPE_P(data) == IS_STRING) {
		ulong h = zend_hash_func(COUCHDB_LAST_RAW_RES, sizeof(COUCHDB_LAST_RAW_RES)); 
	
		return zend_hash_quick_update(hasht, COUCHDB_LAST_RAW_RES, sizeof(COUCHDB_LAST_RAW_RES), h, &data, sizeof(zval *), NULL);
	}
	return FAILURE;
}
/* }}} */

static inline zval **couchdb_get_property(php_couchdb_object *local_client, char *prop_name TSRMLS_DC) /* {{{ */
{
	size_t prop_len = 0;
	void *data_ptr;
	ulong h;
	
	prop_len = strlen(prop_name);
	h = zend_hash_func(prop_name, prop_len+1);
	
	if (zend_hash_quick_find(local_client->properties, prop_name, prop_len+1, h, (void **)&data_ptr) == SUCCESS) {
		return (zval **)data_ptr;
	}
	
	return NULL;
}
/* }}} */

static inline int couchdb_set_property(php_couchdb_object *local_client, zval *prop, char *prop_name TSRMLS_DC) /* {{{ */
{
	size_t prop_len = 0;
	ulong h;
	
	prop_len = strlen(prop_name);
	h = zend_hash_func(prop_name, prop_len+1);
	
	return zend_hash_quick_update(local_client->properties, prop_name, prop_len+1, h, (void *)&prop, sizeof(zval *), NULL);
}
/* }}} */

static void couchdb_hash_dtor(php_couchdb_object *local_client TSRMLS_DC) /* {{{ */
{
	HashTable *ht;
	
	ht = local_client->properties;
	
	FREE_ARGS_HASH(ht);
}
/* }}} */

static size_t couchdb_read_response(char *ptr, size_t size, size_t nmemb, void *ctx) /* {{{ */
{
	uint relsize;
	php_couchdb_object *local_client = (php_couchdb_object *)ctx;
	
	relsize = size * nmemb;
	smart_str_appendl(&local_client->lastresponse, ptr, relsize);
	
	return relsize;
}
/* }}} */

static size_t couchdb_write_response(void *ptr, size_t size, size_t nmemb, void *ctx) /* {{{ */
{
	php_couchdb_object *local_client = (php_couchdb_object *)ctx;
	
	if (local_client->lastrequest.len) {
		size_t out = MIN(size * nmemb, local_client->lastrequest.len - local_client->previous);
		if (out) {
			memcpy(ptr, ((char *) local_client->lastrequest.c) + local_client->previous, out);
			local_client->previous += out;
			return out;
		}
	}
	
	return 0;
}
/* }}} */

static CURLcode couchdb_make_request(php_couchdb_object *local_client, const char *url, const smart_str *payload, const char *http_method, HashTable *request_headers TSRMLS_DC) /* {{{ */
{
	CURLcode cres, crres, cookie_result;
	CURL *curl;
	zval **zca_info, **zca_path;
	void *p_cur;
	struct curl_slist *curl_headers = NULL, *cookies, *cookie_itr;
	long response_code = -1;
	char *current_key;
	smart_str rheader = {0};
	uint current_key_len;
	ulong num_key;
	
	zca_info = couchdb_get_property(local_client, COUCHDB_CA_INFO TSRMLS_CC);
	zca_path = couchdb_get_property(local_client, COUCHDB_CA_PATH TSRMLS_CC);
	
	curl = curl_easy_init();
	
	curl_headers = curl_slist_append(curl_headers, COUCHDB_ACCEPT_HEADERS);
	
	if (request_headers) {
		for (zend_hash_internal_pointer_reset(request_headers); zend_hash_get_current_data(request_headers, (void **)&p_cur) == SUCCESS;
			zend_hash_move_forward(request_headers)) {
			if (HASH_KEY_IS_STRING == zend_hash_get_current_key_ex(request_headers, &current_key, &current_key_len, &num_key, 0, NULL)) {
				smart_str_appends(&rheader, current_key);
				smart_str_appends(&rheader, ": ");
				smart_str_appends(&rheader, Z_STRVAL_PP((zval **)p_cur));
				smart_str_0(&rheader);
				curl_headers = curl_slist_append(curl_headers, rheader.c);
				smart_str_free(&rheader);
			}
		}
	}
	
	if (payload->len) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload->c);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload->len);
	}
	
	if (local_client->lastrequest.len && strcmp(http_method, COUCHDB_PUT) == 0) {
		curl_easy_setopt(curl, CURLOPT_PUT, TRUE);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, TRUE);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, couchdb_write_response);
		curl_easy_setopt(curl, CURLOPT_READDATA, local_client);
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, local_client->lastrequest.len);
#if !defined(ZTS)
        curl_headers = curl_slist_append(curl_headers, "Transfer-Encoding: chunked");
#endif		
	}
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	if(zca_path && Z_STRLEN_PP(zca_path)) {
		curl_easy_setopt(curl, CURLOPT_CAPATH, Z_STRVAL_PP(zca_path));
	}
	
	if(zca_info && Z_STRLEN_PP(zca_info)) {
		curl_easy_setopt(curl, CURLOPT_CAINFO, Z_STRVAL_PP(zca_info));
	}
	
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
	
	if (local_client->use_cookie_auth) {
		curl_easy_setopt(curl, CURLOPT_COOKIE, local_client->cookie.c);
		curl_headers = curl_slist_append(curl_headers, "X-CouchDB-WWW-Authenticate: Cookie");
		curl_headers = curl_slist_append(curl_headers, "Authorization:");
	}
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, http_method);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 4L);
	curl_headers = curl_slist_append(curl_headers, "Expect:");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, couchdb_read_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, local_client);
#if defined(ZTS)	
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
#endif
	
	smart_str_free(&local_client->lastresponse);
	
	cres = curl_easy_perform(curl);
	
	smart_str_0(&local_client->lastresponse);
	smart_str_free(&local_client->lastrequest);
	
	curl_slist_free_all(curl_headers);
	
	if (CURLE_OK == cres) {
		crres = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		cookie_result = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
		if (CURLE_OK == cookie_result) {
			char *token, *p;
			int x = 1;
			
			cookie_itr = cookies;
			while (cookie_itr) {
				p = php_strtok_r(cookie_itr->data, "\t", &token);
				while (p) {
					if (x == 6) {
						smart_str_free(&local_client->cookie);
						smart_str_appends(&local_client->cookie, p);
						smart_str_appendc(&local_client->cookie, '=');
					}else if (x == 7) {
						smart_str_appends(&local_client->cookie, p);
					}
					x++;
					p = php_strtok_r(NULL, "\t", &token);
				}	
				cookie_itr = cookie_itr->next;
			}
			smart_str_0(&local_client->cookie);
			curl_slist_free_all(cookies);
		}else {
			php_error(E_WARNING, COUCHDB_COOKIE_NOT_GOT);
		}
	}else {
		crres = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		php_error(E_WARNING, COUCHDB_SERVER_FAIL, local_client->lastresponse.c);
	}
	curl_easy_cleanup(curl);
	
	return response_code;
}
/* }}} */

static long couchdb_prepare_request(php_couchdb_object *local_client, const char *url, const char *method, zval *request_params, HashTable *request_headers, int get_flags TSRMLS_DC) /* {{{ */
{
	long http_response_code;
	smart_str surl = {0}, payload = {0}, postdata = {0};
	HashTable *rargs = NULL;
	
	if (request_params) {
		switch (Z_TYPE_P(request_params)) {
			case IS_ARRAY:
				rargs = HASH_OF(request_params);
				couchdb_build_query(&postdata, rargs, 0);
				break;
			case IS_STRING:
				smart_str_appendl(&postdata, Z_STRVAL_P(request_params), Z_STRLEN_P(request_params));
				break;
		}
	}
	
	smart_str_0(&postdata);
	smart_str_0(&surl);
	smart_str_appends(&surl, url);
	
	http_response_code = -1;
	
	
	if (strcmp(method, COUCHDB_GET) == 0 || strcmp(method, COUCHDB_DELETE) == 0) {
		if (postdata.len) {
			smart_str_append(http_url_concat(&surl), &postdata);
		}
	}else {
		if (get_flags && postdata.len) {
			smart_str_append(http_url_concat(&surl), &postdata);
		}else {
			smart_str_append(&payload, &postdata);
			smart_str_0(&payload);
		}
	}
	
	smart_str_0(&surl);
	
	http_response_code = couchdb_make_request(local_client, surl.c, &payload, method, request_headers TSRMLS_CC);
	
	smart_str_free(&payload);
	
	if (http_response_code < COUCHDB_STATUS_OK || http_response_code > COUCHDB_STATUS_END) {
		http_response_code = -1;
	}
	
	smart_str_free(&surl);
	smart_str_free(&postdata);
	
	return http_response_code;
}
/* }}} */

static int couchdb_cookie_login(php_couchdb_object *local_client, char *url, char *user_name, char *password TSRMLS_DC) /* {{{ */
{
	zval *auth_string;
	char *buff, *euser_name, *epassword;
	int tlen = 0;
	long http_response_code;
	
	
	euser_name = couchdb_encode_url(user_name);
	epassword = couchdb_encode_url(password);
	
	tlen = spprintf(&buff, 0, "username=%s&password=%s", euser_name, epassword);
	
	MAKE_STD_ZVAL(auth_string);
	ZVAL_STRINGL(auth_string, buff, tlen, 1);
	
	efree(euser_name);
	efree(epassword);
	efree(buff);
	
	http_response_code = couchdb_prepare_request(local_client, url, COUCHDB_POST, auth_string, NULL, 0 TSRMLS_CC);
	
	zval_ptr_dtor(&auth_string);
	
	if (http_response_code == COUCHDB_STATUS_OK) {
		return TRUE;
	}else {
		return FALSE;
	}
	
}
/* }}} */

static int couchdb_cookie_logout(php_couchdb_object *local_client, char *url TSRMLS_DC) /* {{{ */
{
	long http_response_code;
	
	http_response_code = couchdb_prepare_request(local_client, url, COUCHDB_DELETE, NULL, NULL, 0 TSRMLS_CC);
	
	if (http_response_code == COUCHDB_STATUS_OK) {
		return TRUE;
	}else {
		return FALSE;
	}
}
/* }}} */

static inline php_couchdb_object *fetch_couchdb_object(zval *obj TSRMLS_DC) /* {{{ */
{
	php_couchdb_object *local_client = (php_couchdb_object *)zend_object_store_get_object(obj TSRMLS_CC);
	
	local_client->this_ptr	= obj;
	
	return local_client;
}
/* }}} */

static zval *couchdb_read_member(zval *obj, zval *mem, int type, const zend_literal *key TSRMLS_DC) /* {{{ */
{
	zval *return_value = NULL;
	php_couchdb_object *local_client;
	
	local_client = fetch_couchdb_object(obj TSRMLS_CC);
	
	return_value = zend_get_std_object_handlers()->read_property(obj, mem, type, key TSRMLS_CC);
	
	return return_value;
	
} 
/* }}} */

static void couchdb_write_member(zval *obj, zval *mem, zval *value, const zend_literal *key TSRMLS_DC) /* {{{ */
{
	char *property;
	php_couchdb_object *local_client;
	
	property = Z_STRVAL_P(mem);
	local_client = fetch_couchdb_object(obj TSRMLS_CC);
	
	zend_get_std_object_handlers()->write_property(obj, mem, value, key TSRMLS_CC);
}
/* }}} */

static void couchdb_object_free_storage(void *obj TSRMLS_DC) /* {{{ */
{
	php_couchdb_object *local_client;
	
	local_client = (php_couchdb_object *) obj;
	
	zend_object_std_dtor(&local_client->std TSRMLS_CC);
	
	if (local_client->lastresponse.c) {
		smart_str_free(&local_client->lastresponse);
	}
	
	if (local_client->lastrequest.c) {
		smart_str_free(&local_client->lastrequest);
	}
	
	if (local_client->cookie.c) {
		smart_str_free(&local_client->cookie);
	}
	
	efree(obj);
}
/* }}} */

static zend_object_value couchdb_client_new(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
	zend_object_value retval;
	php_couchdb_object *local_client;
	
	local_client = ecalloc(1, sizeof(php_couchdb_object));
	zend_object_std_init(&(local_client->std), ce TSRMLS_CC);
	
	retval.handle = zend_objects_store_put(local_client, (zend_objects_store_dtor_t)zend_objects_destroy_object, couchdb_object_free_storage, NULL TSRMLS_CC);
	retval.handlers = (zend_object_handlers *) &couchdb_client_handlers;
	
	return retval;
}
/* }}} */

static void _couchdb_getdbinfo(INTERNAL_FUNCTION_PARAMETERS, int type) /* {{{ */
{
	php_couchdb_object *local_client;
	char *url = NULL, *db_name, *edb_name;
	int db_name_len = 0;
	smart_str surl = {0};
	long http_response_code;
	zend_bool assoc = 1;
	zval * zret = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &db_name, &db_name_len) == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	if (!db_name_len) {
		CHECK_DB_NAME(local_client);
	}
	
	edb_name = couchdb_encode_url(db_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	smart_str_0(&surl);
	
	efree(edb_name);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, NULL, NULL, 0 TSRMLS_CC);

	smart_str_free(&surl);	

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

static void _couchdb_sendrequest(INTERNAL_FUNCTION_PARAMETERS, int type, zend_bool throw_exception) /* {{{ */
{
	php_couchdb_object *local_client;
	char *url = NULL, *db_name, *edb_name, *ldb_name=NULL;
	int db_name_len = 0;
	smart_str surl = {0};
	long http_response_code, comp_response;
	zval * zret = NULL, *dbp = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &db_name, &db_name_len) == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	if (!db_name_len) {
		CHECK_DB_NAME(local_client);
	}
	
	edb_name = couchdb_encode_url(db_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	if (type == COUCHDB_DB_COMPACT) {
		smart_str_appends(&surl, COUCHDB_COMPACT);
	}
	smart_str_0(&surl);
	
	efree(edb_name);
	
	if (type == COUCHDB_DB_COMPACT) {
		comp_response = COUCHDB_STATUS_ACCEPTED;
		http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_POST, NULL, NULL, 0 TSRMLS_CC);
	}else if (type == COUCHDB_DB_DELETE) {
		comp_response = COUCHDB_STATUS_OK;
		http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_DELETE, NULL, NULL, 0 TSRMLS_CC);
		
		ldb_name = "";
		MAKE_STD_ZVAL(dbp);
        ZVAL_STRING(dbp, ldb_name, 1);
		
        if (couchdb_set_property(local_client, dbp, COUCHDB_DB TSRMLS_CC) != SUCCESS) {
			COUCHDB_ERROR(0, COUCHDB_DB_DESELECT_FAIL);
            return;
        }
	}else{
		comp_response = COUCHDB_STATUS_CREATED;
		http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_PUT, NULL, NULL, 0 TSRMLS_CC);
	}

	
	smart_str_free(&surl);	
	
	if (throw_exception) {
		PROCESS_BOOL_RESULT_EX(http_response_code, local_client, comp_response);
	}else {
		PROCESS_BOOL_RESULT(http_response_code, local_client, comp_response);
	}

}
/* }}} */

/* ---- METHODS ---- */

/* {{{ proto void CouchdbClient::__construct(string url [,bool use_cookie_auth [, string db_name]]) 
 Constructor of the CouchdbClient class */
TC_METHOD(__construct)
{
	HashTable *hasht;
	php_couchdb_object *local_client;
	zval *urp, *dbp, *obj = NULL, *zuser_name, *zpassword;
	char *uri, *db_name = NULL, *striped_url;
	smart_str surl = {0};
	int uri_len, db_name_len = 0;
	php_url *urlparts;
	zend_bool use_cookie_auth = 0;
	
	obj = getThis();
	local_client = fetch_couchdb_object(obj TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|bs", &uri, &uri_len, &use_cookie_auth, &db_name, &db_name_len) == FAILURE) {
		return;
	}
	
	if (!uri_len) {
		COUCHDB_ERROR(0, COUCHDB_INVALID_URI);
		return;
	}
	
	urlparts = php_url_parse_ex(uri, strlen(uri)); 
	
	if (!urlparts || !urlparts->host || !urlparts->scheme) {
		COUCHDB_ERROR(0, COUCHDB_INVALID_URI);
		php_url_free(urlparts);
		return;
	}
	
	if ((strcmp(urlparts->scheme, "http") != 0) && (strcmp(urlparts->scheme, "https") != 0)) {
		COUCHDB_ERROR(0, COUCHDB_INVALID_SCHEME, urlparts->scheme);
		php_url_free(urlparts);
 		return;
	}
	
	/* check if user auth details were supplied */
	if ((!urlparts->user || !urlparts->pass) && use_cookie_auth) {
		COUCHDB_ERROR(0, COUCHDB_COOKIE_PARAMS);
		php_url_free(urlparts);
		return;
	}
	
	local_client->cookie.c = NULL;
	local_client->lastresponse.c = NULL;
	local_client->lastrequest.c = NULL;
	local_client->previous = 0;
	local_client->use_cookie_auth = 0;
	
	if (!db_name_len) {
		db_name = "";
	}
	
	TSRMLS_SET_CTX(local_client->thread_ctx);
	
	if (local_client->properties) {
		zend_hash_clean(local_client->properties);
		hasht = local_client->properties;
	}else {
		ALLOC_HASHTABLE(hasht);
		zend_hash_init(hasht, 0, NULL, ZVAL_PTR_DTOR, 0);
		local_client->properties = hasht;
	}

	MAKE_STD_ZVAL(urp);
	ZVAL_STRINGL(urp, uri, uri_len, 1);
	if (couchdb_set_property(local_client, urp, COUCHDB_URL TSRMLS_CC) != SUCCESS) {
		return;
	}
	
	MAKE_STD_ZVAL(dbp);
	ZVAL_STRINGL(dbp, db_name, db_name_len, 1);
	if (couchdb_set_property(local_client, dbp, COUCHDB_DB TSRMLS_CC) != SUCCESS) {
		return;
	}
	
	if (use_cookie_auth) {
		/* do cookie login */
		if (urlparts->port) {
			spprintf(&striped_url, 0, "%s://%s:%d", urlparts->scheme, urlparts->host, urlparts->port);
			smart_str_appends(&surl, striped_url);
			smart_str_appends(&surl, COUCHDB_SESSION);
			smart_str_0(&surl);
		}else {
			spprintf(&striped_url, 0, "%s://%s", urlparts->scheme, urlparts->host);
			smart_str_appends(&surl, striped_url);
			smart_str_appends(&surl, COUCHDB_SESSION);
			smart_str_0(&surl);
		}
		
		if (couchdb_cookie_login(local_client, surl.c, urlparts->user, urlparts->pass TSRMLS_CC) == 0) {
			COUCHDB_ERROR(0, COUCHDB_COOKIE_AUTH_FAILURE);
			FREE_ARGS_HASH(local_client->properties);
			efree(striped_url);
			php_url_free(urlparts);
			smart_str_free(&surl);
			return;
		}
		
		smart_str_free(&surl);
		uri = striped_url;
		efree(striped_url);
		
		local_client->use_cookie_auth = 1;
	}
	
	MAKE_STD_ZVAL(zuser_name);
	MAKE_STD_ZVAL(zpassword);
	
	if (use_cookie_auth) {
		ZVAL_STRING(zuser_name, urlparts->user, 1);
		ZVAL_STRING(zpassword, urlparts->pass, 1);
	}else {
		ZVAL_STRING(zuser_name, "", 1);
		ZVAL_STRING(zpassword, "", 1);
	}
	
	php_url_free(urlparts);
	
	if (couchdb_set_property(local_client, zuser_name, COUCHDB_USER TSRMLS_CC) != SUCCESS) {
		return;
	}

	if (couchdb_set_property(local_client, zpassword, COUCHDB_PASSWORD TSRMLS_CC) != SUCCESS) {
		return;
	}
	
}
/* }}} */

/* {{{ CouchdbClient::__destruct 
 Destructor for CouchdbClient */
TC_METHOD(__destruct)
{
	php_couchdb_object *local_client;
	char *url;
	smart_str surl = {0};
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}
	
	if (local_client->cookie.c) {
		url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
		
		smart_str_appends(&surl, url);
		smart_str_appends(&surl, COUCHDB_SESSION);
		smart_str_0(&surl);
		
		couchdb_cookie_logout(local_client, surl.c TSRMLS_CC);
		smart_str_free(&local_client->cookie);
		smart_str_free(&surl);
	}
	
	couchdb_hash_dtor(local_client TSRMLS_CC);
}
/* }}} */

/* {{{ proto bool CouchdbClient::compactDatabase([, string db_name ])
Compacts a CouchDB database
 	*/
TC_METHOD(compactDatabase)
{	
	_couchdb_sendrequest(INTERNAL_FUNCTION_PARAM_PASSTHRU, COUCHDB_DB_COMPACT, FALSE);
}
/* }}} */

/* {{{ proto bool CouchdbClient::createDatabase([, string db_name ])
Creates a CouchDB database
Returns true on success and false for failure.
 	*/
TC_METHOD(createDatabase)
{
	_couchdb_sendrequest(INTERNAL_FUNCTION_PARAM_PASSTHRU, COUCHDB_DB_NONE, TRUE);
}
/* }}} */

/* {{{ proto bool CouchdbClient::deleteDatabase([, string db_name])
Drops (deletes) a CouchDB database
 	*/
TC_METHOD(deleteDatabase)
{
	_couchdb_sendrequest(INTERNAL_FUNCTION_PARAM_PASSTHRU, COUCHDB_DB_DELETE, TRUE);
}
/* }}} */

/* {{{ proto array CouchdbClient::getDatabaseInfo([, string db_name ])
Returns CouchDB database information
 	*/
TC_METHOD(getDatabaseInfo)
{
	_couchdb_getdbinfo(INTERNAL_FUNCTION_PARAM_PASSTHRU, COUCHDB_DB_INFO);
}
/* }}} */

/* {{{ proto array CouchdbClient::getDatabaseChanges([, array query_options ])
Returns CouchDB database change history
 	*/
TC_METHOD(getDatabaseChanges)
{
	php_couchdb_object *local_client;
	char *url = NULL, *db_name, *edb_name;
	int db_name_len = 0;
	smart_str surl = {0};
	long http_response_code;
	zend_bool assoc = 1;
	zval * zret = NULL, *query_options;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|a", &query_options) == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	edb_name = couchdb_encode_url(db_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, COUCHDB_CHANGES);

	smart_str_0(&surl);
	
	efree(edb_name);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, query_options, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);	
	
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
}
/* }}} */

/* {{{ proto array CouchdbClient::getAllDocs([, bool by_sequence [, array query_options]])
Returns all CouchDB documents in the database
 	*/
TC_METHOD(getAllDocs)
{
	php_couchdb_object *local_client;
	zval *query_options = NULL, *zret;
	char *db_name = NULL, *edb_name = NULL, *url = NULL;
	smart_str surl = {0};
	int db_name_len = 0;
	long http_response_code;
	zend_bool by_sequence = 0, assoc = 1;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ba", &by_sequence, &query_options) == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	edb_name = couchdb_encode_url(db_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	if (by_sequence) {
		smart_str_appends(&surl, COUCHDB_ALL_DOCS_SEQ);
	}else {
		smart_str_appends(&surl, COUCHDB_ALL_DOCS);
	}
	smart_str_0(&surl);
	
	efree(edb_name);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, query_options, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto object CouchdbClient::getDoc(string doc_id [, array options])
 Returns a CouchDB document from the database
 	*/
TC_METHOD(getDoc)
{
	php_couchdb_object *local_client;
	char *doc_id = NULL, *db_name = NULL, *edb_name = NULL, *url = NULL, *edoc_id;
	int doc_id_len = 0, db_name_len = 0;
	smart_str surl = {0};
	zval *options = NULL, *zret;
	long http_response_code;
	zend_bool assoc = 0;
	zend_bool raw = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ab", &doc_id, &doc_id_len, &options, &raw) == FAILURE) {
		return;
	}
	
	if (!doc_id_len) {
		COUCHDB_ERROR(0, COUCHDB_EMPTY_PARAMS);
		return;
	}

	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	edb_name = couchdb_encode_url(db_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	if (raw) {
		edoc_id = doc_id;
	} else {
		edoc_id = couchdb_encode_url(doc_id);
	}
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edoc_id);
	smart_str_0(&surl);
	
	efree(edb_name);
	efree(edoc_id);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, options, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART_EX(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT_EX(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto object CouchdbClient::storeDoc(mixed document)
 Stores or updates a CouchDB document
 	*/
TC_METHOD(storeDoc)
{
	php_couchdb_object *local_client;
	char *doc_id = NULL, *db_name = NULL, *edb_name = NULL, *url = NULL, *edoc_id, *tmp_document = NULL, *http_method = COUCHDB_PUT;
	int doc_id_len = 0, db_name_len = 0, tmp_document_len = 0;
	smart_str surl = {0}, json_string = {0};
	zval *document = NULL, **zdoc_id = NULL, *zjson_string, *zret, *tmp_json_object;
	long http_response_code;
	zend_bool assoc = 0, document_is_string = 0, got_doc_id = 0;
	HashTable *zdocument_array = NULL;
    HashTable *rheaders = NULL;
	
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &document) == FAILURE) {
		return;
	}
	
	if ((Z_TYPE_P(document) != IS_ARRAY) && (Z_TYPE_P(document) != IS_OBJECT) && (Z_TYPE_P(document) != IS_STRING)) {
		COUCHDB_ERROR(0, COUCHDB_DOC_PARAM_TYPE);
		return;
	}
	
	switch (Z_TYPE_P(document)) {
		case IS_ARRAY:
			zdocument_array = HASH_OF(document);
			
			if (zend_hash_find(zdocument_array, "_id", sizeof("_id"), (void**)&zdoc_id) == SUCCESS){
				got_doc_id = 1;
			}
			break;
		case IS_OBJECT:
			if (zend_hash_find(Z_OBJPROP_P(document), "_id", sizeof("_id"), (void**)&zdoc_id) == SUCCESS){
				got_doc_id = 1;
			}
			break;
		case IS_STRING:
			document_is_string = 1;
			tmp_document = Z_STRVAL_P(document);
			tmp_document_len = Z_STRLEN_P(document);
			
			MAKE_STD_ZVAL(tmp_json_object);
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
			long depth = JSON_PARSER_DEFAULT_DEPTH;
			
			php_json_decode(tmp_json_object, tmp_document, tmp_document_len, assoc, depth TSRMLS_CC);
#else
			php_json_decode(tmp_json_object, tmp_document, tmp_document_len, assoc TSRMLS_CC);
#endif
			if (Z_TYPE_P(tmp_json_object) == IS_OBJECT) {
				if (zend_hash_find(Z_OBJPROP_P(tmp_json_object), "_id", sizeof("_id"), (void**)&zdoc_id) == SUCCESS){
					got_doc_id = 1;
				}
				efree(tmp_json_object);
			}else {
				efree(tmp_json_object);
				COUCHDB_ERROR(0, COUCHDB_INVALID_JSON_STRING);
				return;
			}
			break;
	}
	
	if (got_doc_id) {
		if (Z_TYPE_PP(zdoc_id) != IS_STRING) {
			convert_to_string_ex(zdoc_id);
			doc_id = Z_STRVAL_PP(zdoc_id);
			doc_id_len = Z_STRLEN_PP(zdoc_id);
		}else {
			doc_id = Z_STRVAL_PP(zdoc_id);
			doc_id_len = Z_STRLEN_PP(zdoc_id);
		}
	}
	
	if (!document_is_string) {
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
		long json_options = 0;
		
		php_json_encode(&json_string, document, json_options TSRMLS_CC);
#else
		php_json_encode(&json_string, document TSRMLS_CC);
#endif
		
		if (!json_string.len) {
			COUCHDB_ERROR(0, COUCHDB_JSON_ENCODE_FAIL);
			smart_str_free(&json_string);
			return;
		}
		
		if (strcmp(json_string.c, "null") == 0) {
			COUCHDB_ERROR(0, COUCHDB_JSON_ENCODE_NULL);
			smart_str_free(&json_string);
			return;
		}
	}

	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	edb_name = couchdb_encode_url(db_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	if (doc_id_len) {
		smart_str_appendc(&surl, '/');
		edoc_id = couchdb_encode_url(doc_id);
		smart_str_appends(&surl, edoc_id);
	}
	smart_str_0(&surl);
	
	efree(edb_name);
	if (doc_id_len) {
		efree(edoc_id);
	}
	
	if (!doc_id_len) {
		http_method = COUCHDB_POST;
	}
	
	//add json header
    ALLOC_HASHTABLE(rheaders);
    zend_hash_init(rheaders, 0, NULL, ZVAL_PTR_DTOR, 0);
    
    couchdb_add_req_arg(rheaders, "Content-Type", "application/json" TSRMLS_CC);
	
	if (!document_is_string) {
		smart_str_0(&json_string);
		
		MAKE_STD_ZVAL(zjson_string);
		ZVAL_STRINGL(zjson_string, json_string.c, json_string.len, 1);
		
		http_response_code = couchdb_prepare_request(local_client, surl.c, http_method, zjson_string, rheaders, 0 TSRMLS_CC);
		
		zval_ptr_dtor(&zjson_string);
		smart_str_free(&json_string);
	}else {
		http_response_code = couchdb_prepare_request(local_client, surl.c, http_method, document, rheaders, 0 TSRMLS_CC);
	}
	
    smart_str_free(&surl);
    FREE_ARGS_HASH(rheaders);
	
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)	
	PROCESS_JSON_RESULT_COMPART_EX(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT_EX(http_response_code, local_client, assoc);
#endif
}
/* }}} */

/* {{{ proto bool CouchdbClient::deleteDoc(string doc_id, string rev)
 Deletes a CouchDB document
 	*/
TC_METHOD(deleteDoc)
{
	php_couchdb_object *local_client;
	zval *zret;
	char *db_name = NULL, *edb_name = NULL, *url = NULL, *doc_id, *rev, *edoc_id;
	smart_str surl = {0};
	int db_name_len = 0, doc_id_len = 0, rev_len = 0;
	long http_response_code;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &doc_id, &doc_id_len, &rev, &rev_len) == FAILURE) {
		return;
	}
	
	if (!doc_id_len || !rev_len) {
		COUCHDB_ERROR(0, COUCHDB_EMPTY_PARAMS);
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	edb_name = couchdb_encode_url(db_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	edoc_id = couchdb_encode_url(doc_id);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edoc_id);
	smart_str_appends(&surl, "?rev=");
	smart_str_appends(&surl, rev);
	smart_str_0(&surl);
	
	efree(edb_name);
	efree(edoc_id);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_DELETE, NULL, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);
	
	PROCESS_BOOL_RESULT_EX(http_response_code, local_client, COUCHDB_STATUS_OK);
}
/* }}} */

/* {{{ proto array CouchdbClient::storeDocs(mixed document [, bool all_or_nothing])
  Stores or updates multiple CouchDB documents */
TC_METHOD(storeDocs)
{
	php_couchdb_object *local_client;
	zval *documents = NULL, *tmp_json_object, *zjson_string, *zret;
	char *db_name, *edb_name, *tmp_document, *url, *final_json_string, *all_or_nothing_str = "false";
	smart_str surl = {0}, json_string = {0};
	int db_name_len = 0, tmp_document_len = 0, final_json_string_len = 0;
	long http_response_code;
	zend_bool all_or_nothing = 0, document_is_string = 0, assoc = 1;
	HashTable *rheaders = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|b", &documents, &all_or_nothing) == FAILURE) {
		return;
	}
	
	if ((Z_TYPE_P(documents) != IS_ARRAY) && (Z_TYPE_P(documents) != IS_OBJECT) && (Z_TYPE_P(documents) != IS_STRING)) {
		COUCHDB_ERROR(0, COUCHDB_DOC_PARAM_TYPE);
		return;
	}
	
	if (Z_TYPE_P(documents) == IS_STRING) {
		document_is_string = 1;
		tmp_document = Z_STRVAL_P(documents);
		tmp_document_len = Z_STRLEN_P(documents);
		
		MAKE_STD_ZVAL(tmp_json_object);
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
		long depth = JSON_PARSER_DEFAULT_DEPTH;
		
		php_json_decode(tmp_json_object, tmp_document, tmp_document_len, assoc, depth TSRMLS_CC);
#else
		php_json_decode(tmp_json_object, tmp_document, tmp_document_len, assoc TSRMLS_CC);
#endif
		if (Z_TYPE_P(tmp_json_object) == IS_OBJECT) {
			efree(tmp_json_object);
		}else {
			efree(tmp_json_object);
			COUCHDB_ERROR(0, COUCHDB_INVALID_JSON_STRING);
			return;
		}
	}else {
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
		long json_options = 0;
		
		php_json_encode(&json_string, documents, json_options TSRMLS_CC);
#else
		php_json_encode(&json_string, documents TSRMLS_CC);
#endif
		
		if (!json_string.len) {
			COUCHDB_ERROR(0, COUCHDB_JSON_ENCODE_FAIL);
			smart_str_free(&json_string);
			return;
		}
		
		if (strcmp(json_string.c, "null") == 0) {
			COUCHDB_ERROR(0, COUCHDB_JSON_ENCODE_NULL);
			smart_str_free(&json_string);
			return;
		}
	}

	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	edb_name = couchdb_encode_url(db_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	smart_str_appends(&surl, COUCHDB_BULK_DOCS);
	smart_str_0(&surl);
	
	efree(edb_name);

	// we should add the json header in every case, either no one will let us on the couch.
	ALLOC_HASHTABLE(rheaders);
	zend_hash_init(rheaders, 0, NULL, ZVAL_PTR_DTOR, 0);
	couchdb_add_req_arg(rheaders, "Content-Type", "application/json" TSRMLS_CC);

	if (!document_is_string) {
		
		if (all_or_nothing) {
			all_or_nothing_str = "true";
		}
		
		smart_str_0(&json_string);
		final_json_string_len = spprintf(&final_json_string, 0, "{\"all_or_nothing\":%s,\"docs\":%s}", all_or_nothing_str, json_string.c);
		
		MAKE_STD_ZVAL(zjson_string);
		ZVAL_STRINGL(zjson_string, final_json_string, final_json_string_len, 1);
		
		smart_str_free(&json_string);

		http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_POST, zjson_string, rheaders, 0 TSRMLS_CC);
		
		zval_ptr_dtor(&zjson_string);
		efree(final_json_string);
	}else {
		http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_POST, documents, rheaders, 0 TSRMLS_CC);
	}
	
	smart_str_free(&surl);
	
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)	
	PROCESS_JSON_RESULT_COMPART_EX(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT_EX(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto object CouchdbClient::getTempView(mixed temp_view)
  Executes a temporary CouchDB view query */
TC_METHOD(getTempView)
{
	php_couchdb_object *local_client;
	zval *temp_view, *tmp_json_object, *zjson_string, *zret;
	char *db_name, *edb_name, *url, *tmp_document;
	smart_str json_string = {0}, surl = {0};
	int db_name_len = 0, tmp_document_len = 0;
	long http_response_code;
	zend_bool document_is_string = 0, assoc = 0;
	HashTable *rheaders = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &temp_view) == FAILURE) {
		return;
	}

	if ((Z_TYPE_P(temp_view) != IS_ARRAY) && (Z_TYPE_P(temp_view) != IS_OBJECT) && (Z_TYPE_P(temp_view) != IS_STRING)) {
		COUCHDB_ERROR(0, COUCHDB_DOC_PARAM_TYPE);
		return;
	}
	
	if (Z_TYPE_P(temp_view) == IS_STRING) {
		document_is_string = 1;
		tmp_document = Z_STRVAL_P(temp_view);
		tmp_document_len = Z_STRLEN_P(temp_view);
		MAKE_STD_ZVAL(tmp_json_object);
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
		long depth = JSON_PARSER_DEFAULT_DEPTH;
		php_json_decode(tmp_json_object, tmp_document, tmp_document_len, assoc, depth TSRMLS_CC);
#else
		php_json_decode(tmp_json_object, tmp_document, tmp_document_len, assoc TSRMLS_CC);
#endif
		if (Z_TYPE_P(tmp_json_object) == IS_OBJECT) {
			efree(tmp_json_object);
		}else {
			efree(tmp_json_object);
			COUCHDB_ERROR(0, COUCHDB_JSON_INVALID);
			return;
		}
	}else {
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
		long json_options = 0;
		php_json_encode(&json_string, temp_view, json_options TSRMLS_CC);
#else
		php_json_encode(&json_string, temp_view TSRMLS_CC);
#endif
		
		if (!json_string.len) {
			COUCHDB_ERROR(0, COUCHDB_JSON_ENCODE_FAIL);
			smart_str_free(&json_string);
			return;
		}
		
		if (strcmp(json_string.c, "null") == 0) {
			COUCHDB_ERROR(0, COUCHDB_JSON_ENCODE_NULL);
			smart_str_free(&json_string);
			return;
		}
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	edb_name = couchdb_encode_url(db_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	smart_str_appends(&surl, COUCHDB_TEMP_VIEW);
	smart_str_0(&surl);
	
	efree(edb_name);
	
	ALLOC_HASHTABLE(rheaders);
	zend_hash_init(rheaders, 0, NULL, ZVAL_PTR_DTOR, 0);
	
	couchdb_add_req_arg(rheaders, "Content-Type", "application/json" TSRMLS_CC);
	
	if (!document_is_string) {
		MAKE_STD_ZVAL(zjson_string);
		ZVAL_STRINGL(zjson_string, json_string.c, json_string.len, 1);
		
		http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_POST, zjson_string, rheaders, 0 TSRMLS_CC);
		
		smart_str_free(&json_string);
		zval_ptr_dtor(&zjson_string);
	}else {
		http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_POST, temp_view, rheaders, 0 TSRMLS_CC);
	}
	
	smart_str_free(&surl);
	FREE_ARGS_HASH(rheaders);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto object CouchdbClient::getView(string design_doc, string view_name [, array query_options])
  Executes a CouchDB view query */
TC_METHOD(getView)
{
	php_couchdb_object *local_client;
	char *db_name, *edb_name, *url, *design_doc, *view_name, *edesign_doc, *eview_name;
	int db_name_len = 0, design_doc_len = 0, view_name_len = 0;
	smart_str surl = {0};
	long http_response_code;
	zval *zret, *query_options;
	zend_bool assoc = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|a", &design_doc, &design_doc_len,
							  &view_name, &view_name_len, &query_options) == FAILURE) {
		return;
	}
	
	if (!view_name_len || !design_doc_len) {
		COUCHDB_ERROR(0, COUCHDB_EMPTY_PARAMS);
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	edb_name = couchdb_encode_url(db_name);
	edesign_doc = couchdb_encode_url(design_doc);
	eview_name = couchdb_encode_url(view_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	smart_str_appends(&surl, "/_design/");
	smart_str_appends(&surl, edesign_doc);
	smart_str_appends(&surl, "/_view/");
	smart_str_appends(&surl, eview_name);
	smart_str_0(&surl);
	
	efree(edb_name);
	efree(edesign_doc);
	efree(eview_name);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, query_options, NULL, 0 TSRMLS_CC);
	smart_str_free(&surl);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto array CouchdbClient::copyDoc(string doc_id, string new_doc_id [, new_doc_revision])
 Copies a CouchDB document
 	*/
TC_METHOD(copyDoc)
{
	php_couchdb_object *local_client;
	zval *zret;
	char *db_name, *edb_name, *doc_id, *new_doc_id, *url, *new_doc_revision, *edoc_id, *enew_doc_id, *buff;
	int db_name_len = 0, doc_id_len = 0, new_doc_id_len = 0, new_doc_revision_len = 0;
	smart_str surl = {0};
	long http_response_code;
	zend_bool assoc = 1;
	HashTable *rheaders = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|s", &doc_id, &doc_id_len, 
							  &new_doc_id, &new_doc_id_len, &new_doc_revision, 
							  &new_doc_revision_len) == FAILURE) {
		return;
	}
	
	if (!doc_id_len || !new_doc_id_len) {
		COUCHDB_ERROR(0, COUCHDB_EMPTY_PARAMS);
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	edb_name = couchdb_encode_url(db_name);
	edoc_id = couchdb_encode_url(doc_id);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edoc_id);
	smart_str_0(&surl);
	
	efree(edb_name);
	efree(edoc_id);
	
	enew_doc_id = couchdb_encode_url(new_doc_id);
	
	ALLOC_HASHTABLE(rheaders);
	zend_hash_init(rheaders, 0, NULL, ZVAL_PTR_DTOR, 0);
	
	if (!new_doc_revision_len) {
		couchdb_add_req_arg(rheaders, "Destination", enew_doc_id TSRMLS_CC);
	}else {
		spprintf(&buff, 0, "%s?rev=%s", enew_doc_id, new_doc_revision);
		couchdb_add_req_arg(rheaders, "Destination", buff TSRMLS_CC);
		efree(buff);
	}

	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_COPY, NULL, rheaders, 0 TSRMLS_CC);
	
	efree(enew_doc_id);
	smart_str_free(&surl);
	FREE_ARGS_HASH(rheaders);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART_EX(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT_EX(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto array CouchdbClient::storeAttachment(string doc_id, string filename, string attachment_name, string content_type [, string doc_rev])
 Stores an an attachment to the database
 	*/
TC_METHOD(storeAttachment)
{
	php_couchdb_object *local_client;
	char *db_name, *edb_name, *doc_id, *edoc_id, *filename, *attachment_name, *content_type, *doc_rev, *url;
	char *file_contents, *eattachment_name;
	int db_name_len = 0, doc_id_len = 0, filename_len = 0, attachment_name_len = 0, content_type_len = 0, doc_rev_len = 0, len, new_len;
	smart_str surl = {0};
	php_stream *file_stream;
	zval *zret;
	long http_response_code, maxlen = PHP_STREAM_COPY_ALL;
	zend_bool assoc = 0;
	HashTable *rheaders = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss|s", &doc_id, &doc_id_len, &filename, &filename_len,
							  &attachment_name, &attachment_name_len, &content_type, &content_type_len, &doc_rev, 
							  &doc_rev_len) == FAILURE) {
		return;
	}
	
	if (!doc_id_len || !filename_len || !attachment_name_len || !content_type_len) {
		COUCHDB_ERROR(0, COUCHDB_EMPTY_PARAMS);
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);
	
	file_stream = php_stream_open_wrapper_ex(filename, "rb", 0 | ENFORCE_SAFE_MODE | REPORT_ERRORS, NULL, NULL);
	if (!file_stream) {
		COUCHDB_ERROR(0, COUCHDB_FILE_OPEN_FAIL, filename);
		return;
	}
	
	if (!((len = php_stream_copy_to_mem(file_stream, &file_contents, maxlen, 0)) > 0)) {
		if (len == 0) {
			COUCHDB_ERROR(0, COUCHDB_FILE_EMPTY, filename);
			return;
		}else {
			COUCHDB_ERROR(0, COUCHDB_FILE_READ_FAIL, filename);
			return;
		}
	}

	php_stream_close(file_stream);
	
	edb_name = couchdb_encode_url(db_name);
	edoc_id = couchdb_encode_url(doc_id);
	eattachment_name = couchdb_encode_url(attachment_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edoc_id);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, eattachment_name);
	if (doc_rev_len) {
		smart_str_appends(&surl, "?rev=");
		smart_str_appends(&surl, doc_rev);
	}
	smart_str_0(&surl);
	
	efree(edb_name);
	efree(edoc_id);
	efree(eattachment_name);
	
	ALLOC_HASHTABLE(rheaders);
	zend_hash_init(rheaders, 0, NULL, ZVAL_PTR_DTOR, 0);
	
	couchdb_add_req_arg(rheaders, "Content-Type", content_type TSRMLS_CC);
	
	smart_str_free(&local_client->lastrequest);
	smart_str_appendl(&local_client->lastrequest, file_contents, len);
	smart_str_0(&local_client->lastrequest);
	
	efree(file_contents);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_PUT, NULL, rheaders, 1 TSRMLS_CC);
	
	smart_str_free(&surl);
	FREE_ARGS_HASH(rheaders);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART_EX(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT_EX(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto array CouchdbClient::deleteAttachment(string doc_id, string attachment_name, string doc_rev)
 Deletes a CouchDB attachment
 	*/
TC_METHOD(deleteAttachment)
{
	php_couchdb_object *local_client;
	zval *zret;
	char *db_name, *edb_name, *doc_id, *edoc_id, *attachment_name, *eattachment_name, *doc_rev, *url;
	int db_name_len = 0, doc_id_len = 0, attachment_name_len = 0, doc_rev_len = 0;
	smart_str surl = {0};
	long http_response_code;
	zend_bool assoc = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &doc_id, &doc_id_len, &attachment_name, 
							  &attachment_name_len, &doc_rev, &doc_rev_len) == FAILURE) {
		return;
	}
	
	if (!doc_id_len || !attachment_name_len || !doc_rev_len) {
		COUCHDB_ERROR(0, COUCHDB_EMPTY_PARAMS);
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	CHECK_DB_NAME(local_client);

	edb_name = couchdb_encode_url(db_name);
	edoc_id = couchdb_encode_url(doc_id);
	eattachment_name = couchdb_encode_url(attachment_name);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edb_name);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, edoc_id);
	smart_str_appendc(&surl, '/');
	smart_str_appends(&surl, eattachment_name);
	smart_str_appends(&surl, "?rev=");
	smart_str_appends(&surl, doc_rev);
	smart_str_0(&surl);
	
	efree(edb_name);
	efree(edoc_id);
	efree(eattachment_name);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_DELETE, NULL, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART_EX(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT_EX(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto array CouchdbClient::getServerInfo()
Returns CouchDB server information */
TC_METHOD(getServerInfo)
{
	php_couchdb_object *local_client;
	char *url = NULL;
	long http_response_code;
	zend_bool assoc = 1;
	zval * zret = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	http_response_code = couchdb_prepare_request(local_client, url, COUCHDB_GET, NULL, NULL, 0 TSRMLS_CC);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto array CouchdbClient::getServerConfig()
Returns CouchDB server configuration */
TC_METHOD(getServerConfig)
{
	php_couchdb_object *local_client;
	char *url = NULL, *group;
	int group_len = 0;
	smart_str surl = {0};
	long http_response_code;
	zend_bool assoc = 1;
	zval * zret = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &group, &group_len) == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appends(&surl, COUCHDB_CONFIG);
	if (group_len) {
		smart_str_appendc(&surl, '/');
		smart_str_appends(&surl, group);
	}
	smart_str_0(&surl);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, NULL, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto array CouchdbClient::getServerStats()
Returns CouchDB server statistics */
TC_METHOD(getServerStats)
{
	php_couchdb_object *local_client;
	char *url = NULL;
	smart_str surl = {0};
	long http_response_code;
	zend_bool assoc = 1;
	zval * zret = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appends(&surl, COUCHDB_STATS);
	smart_str_0(&surl);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, NULL, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);
	
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto array CouchdbClient::listDatabases()
List the databases available on a CouchDB server.
*/
TC_METHOD(listDatabases)
{
	php_couchdb_object *local_client;
	char *url = NULL;
	smart_str surl = {0};
	long http_response_code;
	zend_bool assoc = 1;
	zval * zret = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appends(&surl, COUCHDB_ALL_DBS);
	smart_str_0(&surl);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, NULL, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto array CouchdbClient::listActiveTasks()
 Lists active tasks */
TC_METHOD(listActiveTasks)
{
	php_couchdb_object *local_client;
	char *url;
	smart_str surl = {0};
	long http_response_code;
	zval *zret = NULL;
	zend_bool assoc = 1;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appends(&surl, COUCHDB_ACTIVE_TASK);
	smart_str_0(&surl);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, NULL, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);
	
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
		
}
/* }}} */

/* {{{ proto array CouchdbClient::getUuids([, int count])
 Get server generated uuids */
TC_METHOD(getUuids)
{
	php_couchdb_object *local_client;
	char *url = NULL, *buff = NULL;
	smart_str surl = {0};
	int count = 0;
	long http_response_code;
	zend_bool assoc = 0;
	zval * zret = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &count) == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appends(&surl, COUCHDB_GET_UUIDS);
	if (count) {
		spprintf(&buff, 0, "?count=%d", count);
		smart_str_appends(&surl, buff);
		efree(buff);
	}
	smart_str_0(&surl);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_GET, NULL, NULL, 0 TSRMLS_CC);
	
	smart_str_free(&surl);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
	PROCESS_JSON_RESULT_COMPART(http_response_code, local_client, assoc);
#else
	PROCESS_JSON_RESULT(http_response_code, local_client, assoc);
#endif
	
}
/* }}} */

/* {{{ proto bool CouchdbClient::startReplication(string source, string destination [, bool set_continuous])
Start CouchDB replication
 */
TC_METHOD(startReplication)
{
	php_couchdb_object *local_client;
	char *url = NULL, *source, *destination, *buff;
	int source_len = 0, destination_len = 0, tlen = 0;
	smart_str surl = {0};
	long http_response_code;
	zval * zret = NULL, *zjson_string;
	zend_bool set_continuous = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|b", &source, &source_len, &destination, &destination_len, &set_continuous) == FAILURE) {
		return;
	}
	
	if (!source_len || !destination_len) {
		COUCHDB_ERROR(0, COUCHDB_EMPTY_PARAMS);
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appends(&surl, COUCHDB_REPLICATE);
	smart_str_0(&surl);

	if (set_continuous) {
		tlen = spprintf(&buff, 0, "{\"source\":\"%s\",\"target\":\"%s\",\"continuous\":true}", source, destination);
	}else {
		tlen = spprintf(&buff, 0, "{\"source\":\"%s\",\"target\":\"%s\"}", source, destination);
	}

	MAKE_STD_ZVAL(zjson_string);
	ZVAL_STRINGL(zjson_string, buff, tlen, 1);
	
	efree(buff);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_POST, zjson_string, NULL, 0 TSRMLS_CC);
	
	zval_ptr_dtor(&zjson_string);
	smart_str_free(&surl);	
	
	PROCESS_BOOL_RESULT(http_response_code, local_client, COUCHDB_STATUS_OK);
}
/* }}} */

/* {{{ proto mixed CouchdbClient::getLastResponse([, bool json_decode])
 Get the last recieved CouchDb server response	*/
TC_METHOD(getLastResponse)
{
	php_couchdb_object *local_client;
	zend_bool json_decode = 0, assoc = 0;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &json_decode) == FAILURE) {
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	if (local_client->lastresponse.c) {
		if (json_decode) {
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3) || (PHP_MAJOR_VERSION > 5)
			long depth = JSON_PARSER_DEFAULT_DEPTH;
			php_json_decode(return_value, local_client->lastresponse.c, local_client->lastresponse.len, assoc, depth TSRMLS_CC);
#else
			php_json_decode(return_value, local_client->lastresponse.c, local_client->lastresponse.len, assoc TSRMLS_CC);
#endif
		}else {
			RETURN_STRINGL(local_client->lastresponse.c, local_client->lastresponse.len, 1);
		}
	}
}
/* }}} */

/* {{{ proto bool CouchdbClient::setCAPath(string ca_path, string ca_info)
 Set the Certificate Authority information */
TC_METHOD(setCAPath)
{ 
	php_couchdb_object *local_client;
	char *ca_path, *ca_info;
	int ca_path_len, ca_info_len;
	zval *zca_path, *zca_info;
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ss", &ca_path, &ca_path_len, &ca_info, &ca_info_len) == FAILURE) { 
		return;
	} 
	
	if (ca_path_len) { 
		MAKE_STD_ZVAL(zca_path);
		ZVAL_STRINGL(zca_path, ca_path, ca_path_len, 1);
		if (couchdb_set_property(local_client, zca_path, COUCHDB_CA_PATH TSRMLS_CC) != SUCCESS) { 
			RETURN_NULL();
		} 
	} 
	
	if (ca_info_len) { 
		MAKE_STD_ZVAL(zca_info);
		ZVAL_STRINGL(zca_info, ca_info, ca_info_len, 1);
		if (couchdb_set_property(local_client, zca_info, COUCHDB_CA_INFO TSRMLS_CC) != SUCCESS) { 
			RETURN_NULL();
		} 
	} 
	
	RETURN_TRUE;
} 
/* }}} */

/* {{{ proto array CouchdbClient::getCAPath()
  Get the Certificate Authority information */
TC_METHOD(getCAPath)
{ 
	php_couchdb_object *local_client;
	zval **zca_path, **zca_info;
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) { 
		return;
	} 
	
	zca_info = couchdb_get_property(local_client, COUCHDB_CA_INFO TSRMLS_CC);
	zca_path = couchdb_get_property(local_client, COUCHDB_CA_PATH TSRMLS_CC);
	
	array_init(return_value);
	
	if (zca_info || zca_path) { 
		if(zca_info) { 
			add_assoc_stringl(return_value, "ca_info", Z_STRVAL_PP(zca_info), Z_STRLEN_PP(zca_info), 1);
		} 
        
		if(zca_path) { 
			add_assoc_stringl(return_value, "ca_path", Z_STRVAL_PP(zca_path), Z_STRLEN_PP(zca_path), 1);
		} 
	} 
} 
/* }}} */

/* {{{ proto bool CouchdbClient::selectDB(string db_name)
Selects a CouchDb database
 */
TC_METHOD(selectDB)
{
	char *db_name = NULL;
	int db_name_len = 0;
	php_couchdb_object *local_client;
	zval *dbp = NULL;
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &db_name, &db_name_len) == FAILURE) {
		return;
	}
	
	if (!db_name_len) {
		COUCHDB_ERROR(0, COUCHDB_EMPTY_PARAMS);
		return;
	}
	
	MAKE_STD_ZVAL(dbp);
	ZVAL_STRINGL(dbp, db_name, db_name_len, 1);
	
	if (couchdb_set_property(local_client, dbp, COUCHDB_DB TSRMLS_CC) != SUCCESS) {
		return;
	}
	
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool CouchdbClient::createAdminUser(string user_name, string password)
 Creates and admin user */
TC_METHOD(createAdminUser)
{
	php_couchdb_object *local_client;
	char *url, *user_name, *password, *euser_name, *epassword, *buff = NULL;
	smart_str surl = {0};
	int user_name_len = 0, password_len = 0, tlen = 0;
	long http_response_code;
	zval *zret, *put_payload;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &user_name, &user_name_len, &password, &password_len) == FAILURE) {
		return;
	}
	
	if (!user_name_len || !password_len) {
		COUCHDB_ERROR(0, COUCHDB_EMPTY_PARAMS);
		return;
	}
	
	local_client = fetch_couchdb_object(getThis() TSRMLS_CC);
	
	url = Z_STRVAL_PP(couchdb_get_property(local_client, COUCHDB_URL TSRMLS_CC));
	
	smart_str_appends(&surl, url);
	smart_str_appends(&surl, COUCHDB_CONFIG);
	smart_str_appends(&surl, "/admins/");
	
	euser_name = couchdb_encode_url(user_name);
	epassword = couchdb_encode_url(password);
	
	smart_str_appends(&surl, euser_name);
	smart_str_0(&surl);

	efree(euser_name);
	
	MAKE_STD_ZVAL(put_payload);
	tlen = spprintf(&buff, 0, "\"%s\"", epassword);
	ZVAL_STRINGL(put_payload, buff, tlen, 1);
	
	efree(buff);
	efree(epassword);
	
	http_response_code = couchdb_prepare_request(local_client, surl.c, COUCHDB_PUT, put_payload, NULL, 0 TSRMLS_CC);
	
	zval_ptr_dtor(&put_payload);
	smart_str_free(&surl);	
	
	PROCESS_BOOL_RESULT(http_response_code, local_client, COUCHDB_STATUS_OK);
	
}
/* }}} */

/* {{{ arginfo */

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_noparams, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_client__construct, 0,0,1)
	ZEND_ARG_INFO(0, uri)
	ZEND_ARG_INFO(0, use_cookie_auth)
	ZEND_ARG_INFO(0, db_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_getdbinfo, 0, 0, 0)
	ZEND_ARG_INFO(0, db_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_getdoc, 0, 0, 1)
	ZEND_ARG_INFO(0, doc_id)
	ZEND_ARG_ARRAY_INFO(0, options, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_getalldocs, 0, 0, 0)
	ZEND_ARG_INFO(0, by_sequence)
	ZEND_ARG_ARRAY_INFO(0, query_options, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_copydoc,	0, 0, 2)
	ZEND_ARG_INFO(0, doc_id)
	ZEND_ARG_INFO(0, new_doc_id)
	ZEND_ARG_INFO(0, new_doc_revision)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_attach, 0, 0, 4)
	ZEND_ARG_INFO(0, doc_id)
	ZEND_ARG_INFO(0, filename)
	ZEND_ARG_INFO(0, attachment_name)
	ZEND_ARG_INFO(0, content_type)
	ZEND_ARG_INFO(0, doc_rev)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_delattach, 0, 0, 2)
	ZEND_ARG_INFO(0, doc_id)
	ZEND_ARG_INFO(0, attachment_name)
	ZEND_ARG_INFO(0, doc_rev)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_setca, 0, 0, 2)
	ZEND_ARG_INFO(0, ca_path)
	ZEND_ARG_INFO(0, ca_info)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_getuuids, 0, 0, 0)
	ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_startrepli, 0, 0, 2)
	ZEND_ARG_INFO(0, source)
	ZEND_ARG_INFO(0, destination)
	ZEND_ARG_INFO(0, set_continuous)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_savedocs, 0, 0, 1)
	ZEND_ARG_INFO(0, documents)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_getview, 0, 0, 2)
	ZEND_ARG_INFO(0, design_doc)
	ZEND_ARG_INFO(0, view_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_gettempview, 0, 0, 1)
	ZEND_ARG_INFO(0, temp_view)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_storedoc, 0, 0, 1)
	ZEND_ARG_INFO(0, document)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_deletedoc, 0, 0, 2)
	ZEND_ARG_INFO(0, doc_id)
	ZEND_ARG_INFO(0, rev)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_getresponse, 0, 0, 0)
	ZEND_ARG_INFO(0, json_decode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_getdbchanges, 0, 0, 0)
	ZEND_ARG_ARRAY_INFO(0, query_options, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_couchdb_createadminuser, 0, 0, 2)
	ZEND_ARG_INFO(0, user_name)
	ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

/* }}} */

static zend_function_entry couchdb_client_methods[] = { /* {{{ */
	TC_ME(__construct,			arginfo_couchdb_client__construct,	ZEND_ACC_PUBLIC|ZEND_ACC_FINAL|ZEND_ACC_CTOR)
	TC_ME(getServerInfo,		arginfo_couchdb_noparams,			ZEND_ACC_PUBLIC)
	TC_ME(getServerConfig,		arginfo_couchdb_noparams,			ZEND_ACC_PUBLIC)
	TC_ME(getServerStats,		arginfo_couchdb_noparams,			ZEND_ACC_PUBLIC)
	TC_ME(listDatabases,		arginfo_couchdb_noparams,			ZEND_ACC_PUBLIC)
	TC_ME(listActiveTasks,		arginfo_couchdb_noparams,			ZEND_ACC_PUBLIC)
	TC_ME(getUuids,				arginfo_couchdb_getuuids,			ZEND_ACC_PUBLIC)
	TC_ME(startReplication,		arginfo_couchdb_startrepli,			ZEND_ACC_PUBLIC)
	TC_ME(createAdminUser,		arginfo_couchdb_createadminuser,	ZEND_ACC_PUBLIC)
	TC_ME(compactDatabase,		arginfo_couchdb_getdbinfo,			ZEND_ACC_PUBLIC)
	TC_ME(createDatabase,		arginfo_couchdb_getdbinfo,			ZEND_ACC_PUBLIC)
	TC_ME(deleteDatabase,		arginfo_couchdb_getdbinfo,			ZEND_ACC_PUBLIC)
	TC_MALIAS(dropDatabase,	deleteDatabase,	arginfo_couchdb_getdbinfo,	ZEND_ACC_PUBLIC)
	TC_ME(getDatabaseInfo,		arginfo_couchdb_getdbinfo,			ZEND_ACC_PUBLIC)
	TC_ME(getDatabaseChanges,	arginfo_couchdb_getdbchanges,		ZEND_ACC_PUBLIC)
	TC_ME(getAllDocs,			arginfo_couchdb_getalldocs,			ZEND_ACC_PUBLIC)
	TC_ME(getDoc,				arginfo_couchdb_getdoc,				ZEND_ACC_PUBLIC)
	TC_ME(storeDoc,				arginfo_couchdb_storedoc,			ZEND_ACC_PUBLIC)
	TC_ME(deleteDoc,			arginfo_couchdb_deletedoc,			ZEND_ACC_PUBLIC)
	TC_ME(storeDocs,			arginfo_couchdb_savedocs,			ZEND_ACC_PUBLIC)
	TC_ME(getTempView,			arginfo_couchdb_gettempview,		ZEND_ACC_PUBLIC)
	TC_ME(getView,				arginfo_couchdb_getview,			ZEND_ACC_PUBLIC)
	TC_ME(copyDoc,				arginfo_couchdb_copydoc,			ZEND_ACC_PUBLIC)
	TC_ME(storeAttachment,		arginfo_couchdb_attach,				ZEND_ACC_PUBLIC)
	TC_ME(deleteAttachment,		arginfo_couchdb_delattach,			ZEND_ACC_PUBLIC)
	TC_ME(getLastResponse,		arginfo_couchdb_getresponse,		ZEND_ACC_PUBLIC)
	TC_ME(setCAPath,			arginfo_couchdb_setca,				ZEND_ACC_PUBLIC)
	TC_ME(getCAPath,			arginfo_couchdb_noparams,			ZEND_ACC_PUBLIC)
	TC_ME(selectDB,				arginfo_couchdb_getdbinfo,			ZEND_ACC_PUBLIC)
	TC_ME(__destruct,			arginfo_couchdb_noparams,			ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
}; 
/* }}} */

zend_function_entry couchdb_functions[] = { /* {{{ */
	{NULL, NULL, NULL}
}; 
/* }}} */

/* {{{ PHP_MINIT_FUNCTION */

PHP_MINIT_FUNCTION(couchdb) 
{ 
	zend_class_entry client_ce;
	
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		return FAILURE;
	}
	
	
	INIT_CLASS_ENTRY(client_ce, COUCHDB_CLASS, couchdb_client_methods);
	client_ce.create_object = couchdb_client_new;
	
	
	couchdb_client_ce_ptr = zend_register_internal_class(&client_ce TSRMLS_CC);
	memcpy(&couchdb_client_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	
	couchdb_client_handlers.read_property = couchdb_read_member;
	couchdb_client_handlers.write_property = couchdb_write_member;
	
	INIT_CLASS_ENTRY(client_ce, COUCHDB_EXCEPTION_CLASS, NULL);
	couchdb_exception_ce_ptr = zend_register_internal_class_ex(&client_ce, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
	
	return SUCCESS;
} /* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION */

PHP_MSHUTDOWN_FUNCTION(couchdb)
{
	couchdb_client_ce_ptr = NULL;
	curl_global_cleanup();
	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION */

PHP_MINFO_FUNCTION(couchdb) 
{ 
	php_info_print_table_start();
	php_info_print_table_header(2, PHP_COUCHDB_NAME, "enabled");
	php_info_print_table_header(2, "Version", PHP_COUCHDB_VERSION);
	php_info_print_table_end();
} 
/* }}} */

/* {{{ couchdb_module_entry */

zend_module_entry couchdb_module_entry = { 
	STANDARD_MODULE_HEADER,
	PHP_COUCHDB_NAME,
	couchdb_functions,
	PHP_MINIT(couchdb),
	PHP_MSHUTDOWN(couchdb),
	NULL,
	NULL,
	PHP_MINFO(couchdb),
	PHP_COUCHDB_VERSION,
	STANDARD_MODULE_PROPERTIES
}; 
/* }}} */

#if COMPILE_DL_COUCHDB
ZEND_GET_MODULE(couchdb)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
