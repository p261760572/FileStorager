#ifndef __http_h
#define __http_h

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifndef MAX_HTTP_HEADERS
#define MAX_HTTP_HEADERS 40
#endif

#ifndef MAX_HTTP_PAIRS
#define MAX_HTTP_PAIRS 20
#endif

#ifndef MAX_REQUEST_SIZE
#define MAX_REQUEST_SIZE 16384
#endif

#define NS_MAX_PATH 4096

typedef struct stat ns_stat_t;

struct net_str_s {
    const char *p;
    size_t len;
};

typedef struct net_str_s net_str_t;

// This structure contains information about HTTP request.
struct http_message_s {
    net_str_t message; /* Whole message: request line + headers + body */

    net_str_t proto; /* "HTTP/1.1" -- for both request and response */

    net_str_t method; /* "GET" */
    net_str_t uri;    /* "/my_file.html" */

    int resp_code;
    net_str_t resp_status_msg;

    net_str_t query_string;

    /* Headers */
    net_str_t header_names[MAX_HTTP_HEADERS];
    net_str_t header_values[MAX_HTTP_HEADERS];

    /* Message body */
    net_str_t body; /* Zero-length for requests with no body */
};

typedef struct http_message_s http_message_t;

struct http_pairs_s {
    net_str_t keys[MAX_HTTP_PAIRS];
    net_str_t values[MAX_HTTP_PAIRS];
};

typedef struct http_pairs_s http_pairs_t;


/* HTTP and websocket events. void *ev_data is described in a comment. */
#define HTTP_REQUEST 100 /* struct http_message * */
#define HTTP_REPLY 101   /* struct http_message * */
#define HTTP_CHUNK 102   /* struct http_message * */
#define SSI_CALL 105     /* char * */


struct net_serve_http_opts_s {
    /* Path to web root directory */
    const char *document_root;

    /* List of index files. */
    const char *index_files;

    /*
     * Comma-separated list of Content-Type overrides for path suffixes, e.g.
     * ".txt=text/plain; charset=utf-8,.c=text/plain"
     */
    const char *custom_mime_types;

	/* Custom headers. */
    const char *custom_headers;
};

typedef struct net_serve_http_opts_s net_serve_http_opts_t;

void net_set_protocol_http(net_connection_t *nc);
void net_serve_http(net_connection_t *nc, http_message_t *hm,
                   net_serve_http_opts_t opts);
int net_parse_http(const char *s, int n, http_message_t *hm, int is_req);
net_str_t *net_get_http_header(http_message_t *hm, const char *name);

net_connection_t *net_connect_http(net_mgr_t *mgr, net_event_handler_t ev_handler,
                               const char *url, const char *extra_headers, const char *post_data,
                               void *user_data);

int net_vcasecmp(const net_str_t *str1, const char *str2);
int net_vcmp(const net_str_t *str1, const char *str2);

int net_url_decode(const char *src, int src_len, char *dst, int dst_len,
                          int is_form_url_encoded);

const char *net_parse_http_cookies(const char *s, const char *end, http_pairs_t *cookies);
net_str_t *net_get_http_cookie(http_pairs_t *cookies, const char *name);
const char *net_parse_http_query_string(const char *s, const char *end, http_pairs_t *query);
net_str_t *net_get_http_query_string(http_pairs_t *query, const char *name);
const char *net_skip(const char *s, const char *end, const char *delims, net_str_t *v);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __http_h
