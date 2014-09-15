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

// hit value to be treated as authorised. needs to be higher than
// sizeof(knock_uris) but stops us having to count each time.
// must be within bounds of data type: ngx_unit_t
#define NGX_HTTP_KNOCK__TARGET_ALLOWED 9999

#define NGX_HTTP_KNOCK__NOT_KNOCK_URI 10000

// configuration related functions

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

// internal red-black tree structure for handling IPs and auth states
typedef struct {
    ngx_rbtree_key_t       key;
    ngx_rbtree_node_t     *left;
    ngx_rbtree_node_t     *right;
    ngx_rbtree_node_t     *parent;
    u_char                 color;
    ngx_uint_t             auth_state;
} ngx_http_knock_node_t;

ngx_rbtree_t *ngx_http_knock_tree;

// extract data from request
ngx_str_t ngx_http_knock_extract_url(ngx_http_request_t *r);
in_addr_t ngx_http_knock_extract_ip_addr(ngx_http_request_t *r);

// find details for IP address
ngx_http_knock_node_t *ngx_http_knock_get_knock_node(in_addr_t ip_addr);
ngx_http_knock_node_t *ngx_http_knock_create_knock_node(in_addr_t ip_addr, ngx_http_request_t *r);
inline ngx_uint_t ngx_http_knock_is_sentinel(ngx_http_knock_node_t *node);

// identify knock details
ngx_uint_t ngx_http_knock_get_knock_uri_index(ngx_array_t *knock_uris, ngx_str_t url);
ngx_uint_t ngx_http_knock_is_successful_knock(ngx_uint_t auth_state, ngx_array_t *knock_uris, ngx_str_t url);

static ngx_int_t
ngx_http_knock_handler(ngx_http_request_t *r)
{
    ngx_http_knock_loc_conf_t  *alcf;
    ngx_http_knock_node_t *request_knock_node;
    ngx_str_t request_url;
    in_addr_t request_ip_addr;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_knock_module);

    if (!alcf->enable) {
        return NGX_OK;
    }

	// pull the only data we care about out of the request
    request_url = ngx_http_knock_extract_url(r);
    request_ip_addr = ngx_http_knock_extract_ip_addr(r);

    // fetch the user's record
    request_knock_node = ngx_http_knock_get_knock_node(request_ip_addr);

    if (!ngx_http_knock_is_sentinel(request_knock_node)) {
        if (request_knock_node->auth_state == NGX_HTTP_KNOCK__TARGET_ALLOWED) {
            // don't intercept traffic.
            return NGX_OK;
        } else if (ngx_http_knock_is_successful_knock(request_knock_node->auth_state, alcf->knock_uris, request_url) == 1) {
            // see if final knock.
            if (request_knock_node->auth_state + 1 == alcf->knock_uris->nelts) {
                request_knock_node->auth_state = NGX_HTTP_KNOCK__TARGET_ALLOWED;
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "ngx_http_knock_module: location unlocked for ip: %s, auth_state: <GRANTED>, uri: %s",
                    request_ip_addr,
                    request_url
                );
            } else
                request_knock_node->auth_state++; // one step closer.
        }
    } else {
        // new ip address. add to knock table only if they've hit first
        // knock url.
        if (ngx_http_knock_get_knock_uri_index(alcf->knock_uris, request_url) == 0)
            request_knock_node = ngx_http_knock_create_knock_node(request_ip_addr, r);
    }

    if (request_knock_node != NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "ngx_http_knock_module: returning 404 for ip: %s, auth_state: %d, uri: %s",
            request_ip_addr,
            request_knock_node->auth_state,
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

// Functions related to extracting data from request

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

// Functions related to finding/storing state information

ngx_http_knock_node_t
*ngx_http_knock_get_knock_node(in_addr_t ip_addr)
{
	ngx_rbtree_node_t *iter;

	iter = ngx_http_knock_tree->root;

	while (!ngx_http_knock_is_sentinel((ngx_http_knock_node_t*)iter)) {
		if (iter->key == ip_addr)
			return (ngx_http_knock_node_t*)iter;
		else if (iter->key < ip_addr)
			iter = iter->left;
		else if (iter->key > ip_addr)
			iter = iter->right;
	}

	return (ngx_http_knock_node_t*)iter;

}

// Assumes node definitely doesn't exist.
// (called right after get_knock_node if it returns a sentinel)
// TODO: don't require r->connection->log here

ngx_http_knock_node_t
*ngx_http_knock_create_knock_node(in_addr_t ip_addr, ngx_http_request_t *r)
{

	ngx_http_knock_node_t *new_node;
	new_node = ngx_alloc(sizeof(ngx_http_knock_node_t), r->connection->log);

	new_node->key = ip_addr;
	new_node->auth_state = 1;

	ngx_rbtree_insert(ngx_http_knock_tree, (ngx_rbtree_node_t*)new_node);

	return new_node;
}

inline ngx_uint_t
ngx_http_knock_is_sentinel(ngx_http_knock_node_t *node)
{
	return ((ngx_rbtree_node_t*)node == ngx_http_knock_tree->sentinel);
}

// Functions related to knocking details

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
ngx_http_knock_is_successful_knock(ngx_uint_t auth_state, ngx_array_t *knock_uris, ngx_str_t url)
{
    ngx_uint_t knock_index;

    knock_index = ngx_http_knock_get_knock_uri_index(knock_uris, url);

    if (knock_index == NGX_HTTP_KNOCK__NOT_KNOCK_URI)
        return 0;

    if (auth_state == knock_index)
        return 1;

    return 0;
}

// Functions related to configuration parsing

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

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_knock_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

	ngx_http_knock_tree = ngx_palloc(cf->pool, sizeof(ngx_rbtree_t));

	ngx_http_knock_node_t *sentinel;
	sentinel = ngx_palloc(cf->pool, sizeof(ngx_http_knock_node_t));
	sentinel->key = 0;
	sentinel->auth_state = -1000;

	ngx_rbtree_init(ngx_http_knock_tree, (ngx_rbtree_node_t*)sentinel, ngx_rbtree_insert_value);

    // install our handler.
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_knock_handler;

    return NGX_OK;
}

