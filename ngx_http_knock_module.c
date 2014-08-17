/*
 * knock module
 *
 * makes website location hidden behind 404 page until
 * other (non-existing) urls are hit. Aka the "port knocking"
 * concept applied to websites. Appropriate for hiding login
 * pages from bots and scanners.
 *
 * This module license matches that of the nginx project.
 * This module is copyright Phillip Taylor <knock@philliptaylor.net>
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

// track at most 30000 ips trying to use system.
// low number = potential denial of service through flushing variable buffer
// low number = reduced maximum allowed connections
// high number = higher ram usage
// must be within bounds of data type: ngx_uint_t
#define NGX_HTTP_KNOCK__IP_DB_SIZE 30000

// hit value to be treated as authorised. needs to be higher than
// sizeof(knock_uris) but stops us having to count each time.
// must be within bounds of data type: ngx_unit_t
#define NGX_HTTP_KNOCK__TARGET_ALLOWED 9999

#define NGX_HTTP_KNOCK__NOT_KNOCK_URI 10000

// configuration

static ngx_int_t ngx_http_knock_handler(ngx_http_request_t *r);
static void *ngx_http_knock_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_knock_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_knock_init(ngx_conf_t *cf);

typedef struct {
    ngx_flag_t    enable;
    ngx_array_t   *knock_uris;
} ngx_http_knock_loc_conf_t;

static ngx_command_t ngx_http_knock_commands[] = {
    { ngx_string("knock_enabled"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_knock_loc_conf_t, enable),
      NULL },
    { ngx_string("knock_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_knock_loc_conf_t, knock_uris),
      NULL },
};

static ngx_http_module_t ngx_http_knock_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_knock_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_knock_create_loc_conf,       /* create location configuration */
    ngx_http_knock_merge_loc_conf         /* merge location configuration */
};

ngx_module_t ngx_http_knock_module = {
    NGX_MODULE_V1,
    &ngx_http_knock_module_ctx,           /* module context */
    ngx_http_knock_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

// data structure for recording access records.

typedef struct _access_record {
    in_addr_t ip_addr;
    ngx_uint_t auth_state; /* where they are in the "hit order" */
} access_record;

access_record access_records[NGX_HTTP_KNOCK__IP_DB_SIZE];

ngx_uint_t ngx_http_knock_next_free_slot;

access_record *ngx_http_knock_get_access_record(in_addr_t ip_addr);
ngx_uint_t ngx_http_knock_get_knock_uri_index(ngx_array_t *knock_uris, ngx_str_t url);
ngx_uint_t ngx_http_knock_is_successful_knock(access_record *request_access_record, ngx_array_t *knock_uris, ngx_str_t url);
access_record *ngx_http_knock_get_free_knock_slot(ngx_array_t *knock_uris);
ngx_str_t ngx_http_knock_extract_url(ngx_http_request_t *r);
in_addr_t ngx_http_knock_extract_ip_addr(ngx_http_request_t *r);

static ngx_int_t
ngx_http_knock_handler(ngx_http_request_t *r)
{
    ngx_http_knock_loc_conf_t  *alcf;
	access_record *request_access_record;
	ngx_str_t request_url;
	in_addr_t request_ip_addr;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_knock_module);

    if (!alcf->enable) {
        return NGX_OK;
    }

	request_url = ngx_http_knock_extract_url(r);
	request_ip_addr = ngx_http_knock_extract_ip_addr(r);

    // search for access record in array (match on ip in request object)
	request_access_record = ngx_http_knock_get_access_record(request_ip_addr);

	if (request_access_record != NULL) {
		if (request_access_record->auth_state == NGX_HTTP_KNOCK__TARGET_ALLOWED) {
			// don't intercept traffic.
    		return NGX_OK;
		} else if (ngx_http_knock_is_successful_knock(request_access_record, alcf->knock_uris, request_url) == 1) {
			// see if final knock.
			if (request_access_record->auth_state + 1 == alcf->knock_uris->nelts) {
				request_access_record->auth_state = NGX_HTTP_KNOCK__TARGET_ALLOWED;
				ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
					"ngx_http_knock_module: location unlocked for ip: %s, auth_state: <GRANTED>, uri: %s",
					request_ip_addr,
					request_url
				);
			} else
				request_access_record->auth_state++; // one step closer.
		}
	} else {
		// new ip address. add to knock table only if they've hit first
		// knock url.
		if (ngx_http_knock_get_knock_uri_index(alcf->knock_uris, request_url) == 0) {
			// add to table
			request_access_record = ngx_http_knock_get_free_knock_slot(alcf->knock_uris);
			request_access_record->ip_addr = request_ip_addr;
			request_access_record->auth_state = 1;
		}
	}

	if (request_access_record != NULL) {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
			"ngx_http_knock_module: returning 404 for ip: %s, auth_state: %d, uri: %s",
			request_ip_addr,
			request_access_record->auth_state,
			request_url
		);
	} else {
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
			"ngx_http_knock_module: returning 404 for ip: %s, auth_state: <NO ENTRY>, uri: %s",
			request_ip_addr,
			request_url
		);
	}

	return NGX_HTTP_NOT_FOUND;

}

access_record
*ngx_http_knock_get_access_record(in_addr_t ip_addr)
{
	ngx_uint_t i;

	for (i = 0; i < NGX_HTTP_KNOCK__IP_DB_SIZE && i < ngx_http_knock_next_free_slot; i++) {
		if (access_records[i].ip_addr == ip_addr)
			return (access_record*)&access_records[i];
	}

	return (access_record*)NULL;
}

ngx_uint_t
ngx_http_knock_get_knock_uri_index(ngx_array_t *knock_uris, ngx_str_t url)
{
	ngx_uint_t i;
	ngx_str_t *__knock_uris;

	if (knock_uris == NGX_CONF_UNSET_PTR)
		return NGX_HTTP_KNOCK__NOT_KNOCK_URI;

	__knock_uris = knock_uris->elts;

	for (i = 0; i < knock_uris->nelts; i++) {
		if (ngx_strncmp((char*)__knock_uris[i].data, (char*)url.data, __knock_uris[i].len) == 0)
			return i;
	}

	return NGX_HTTP_KNOCK__NOT_KNOCK_URI;
}

ngx_uint_t
ngx_http_knock_is_successful_knock(access_record *request_access_record, ngx_array_t *knock_uris, ngx_str_t url)
{
	ngx_uint_t knock_index;

	knock_index = ngx_http_knock_get_knock_uri_index(knock_uris, url);

	if (knock_index == NGX_HTTP_KNOCK__NOT_KNOCK_URI)
		return 0;

	if (request_access_record->auth_state == knock_index)
		return 1;

	return 0;
}

access_record
*ngx_http_knock_get_free_knock_slot(ngx_array_t *knock_uris)
{
	ngx_uint_t i, j;

	if (ngx_http_knock_next_free_slot + 1 == NGX_HTTP_KNOCK__IP_DB_SIZE) {
		// db is full. scan for a record to throw away!
		// discard lowest authed entries first.
		// notice that if you have TARGET_ALLOWED, you wouldn't be
		// subject for deletion as your auth_state is too high.
		for (j = 0; j < knock_uris->nelts; j++) {
			for (i = 0; i < NGX_HTTP_KNOCK__IP_DB_SIZE; i++) {
				if (access_records[i].auth_state == j)
					return &access_records[i];
			}
		}

		//ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
		//		"Sorry no room in ngx_http_knock module's access_records array. please increase NGX_HTTP_KNOCK__IP_DB_SIZE and recompile"
		//);
		return NULL;
	}
	
	return &access_records[ngx_http_knock_next_free_slot++];

}


ngx_str_t
ngx_http_knock_extract_url(ngx_http_request_t *request)
{
	return request->uri;
}

in_addr_t
ngx_http_knock_extract_ip_addr(ngx_http_request_t *r)
{
    struct sockaddr_in *sin;

    sin = (struct sockaddr_in *) r->connection->sockaddr;
	return sin->sin_addr.s_addr;
}

/* this logic is about reading the configuration */

static void *
ngx_http_knock_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_knock_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_knock_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
	conf->knock_uris = NGX_CONF_UNSET_PTR;
    return conf;
}


static char *
ngx_http_knock_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_knock_loc_conf_t  *prev = parent;
    ngx_http_knock_loc_conf_t  *conf = child;
	//ngx_uint_t m, i;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
	// TODO: MERGE ARRAYS
    //ngx_conf_merge_value(conf->knock_uris, prev->knock_uris, 0);
	//if (prev->knock_uris != NGX_CONF_UNSET_PTR) {
	//	if (conf->knock_uris != NGX_CONF_UNSET_PTR) {

	//		// merge arrays
	//		ngx_array_init(


	//		for (i = 0; i < prev->knock_uris->size; i++)
	//			ngx_array_push(
	//	} else {
	//		conf->knock_uris = prev->knock_uris;
	//	}
	//}
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_knock_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_http_knock_next_free_slot = 0;

    // install our handler.
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_knock_handler;

    return NGX_OK;
}

