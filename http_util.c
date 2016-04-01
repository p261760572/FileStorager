#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "http_util.h"

static int parse_range_header(const net_str_t *header, int64_t *a,
                              int64_t *b) {
    /*
     * There is no snscanf. Headers are not guaranteed to be NUL-terminated,
     * so we have this. Ugh.
     */
    int result;
    char *p = (char *) NET_MALLOC(header->len + 1);
    if(p == NULL) return 0;
    memcpy(p, header->p, header->len);
    p[header->len] = '\0';
    result = sscanf(p, "bytes=%" INT64_FMT "-%" INT64_FMT, a, b);
    NET_FREE(p);
    return result;
}


int net_send_http_file2(struct stat *st, char *range_header, char *custom_headers, char *outbuf, int outsize) {
    char range[50];
    int64_t r1 = 0, r2 = 0, cl = st->st_size;
    net_str_t range_hdr;
    int n, status_code = 200;
    const char *status_message = "OK";

	bzero(&range_hdr, sizeof(range_hdr));
	if(range_header != NULL) {
		range_hdr.p = range_header;
		range_hdr.len = strlen(range_header);
	}

    /* Handle Range header */
    range[0] = '\0';
    if(range_hdr.len > 0 &&
       (n = parse_range_header(&range_hdr, &r1, &r2)) > 0 && r1 >= 0 &&
       r2 >= 0) {
        /* If range is specified like "400-", set second limit to content len */
        if(n == 1) {
            r2 = cl - 1;
        }
        if(r1 > r2 || r2 >= cl) {
            status_code = 416;
            status_message = "Requested range not satisfiable";
            cl = 0;
            snprintf(range, sizeof(range),
                     "Content-Range: bytes */%" INT64_FMT "\r\n",
                     (int64_t) st->st_size);
        } else {
            status_code = 206;
            status_message = "Partial Content";
            cl = r2 - r1 + 1;
            snprintf(range, sizeof(range), "Content-Range: bytes %" INT64_FMT
                     "-%" INT64_FMT "/%" INT64_FMT "\r\n",
                     r1, r1 + cl - 1, (int64_t) st->st_size);
            //fseeko(dp->fp, r1, SEEK_SET);
        }
    }

    return snprintf(outbuf, outsize,
               "HTTP/1.1 %d %s\r\n"
               "Accept-Ranges: bytes\r\n"
               "Content-Type: application/octet-stream\r\n"
               "Content-Length: %" INT64_FMT
               "\r\n"
               "%s"
               "%s"
               "\r\n",
               status_code, status_message, cl, range, custom_headers);
}



const char *net_skip(const char *s, const char *end, const char *delims,
                     net_str_t *v) {
    v->p = s;
    while(s < end && strchr(delims, *(unsigned char *) s) == NULL) s++;
    v->len = s - v->p;
    while(s < end && strchr(delims, *(unsigned char *) s) != NULL) s++;
    return s;
}

const char *net_parse_http_cookies(const char *s, const char *end, http_pairs_t *cookies) {
    int i;

    bzero(cookies, sizeof(*cookies));

    for(i = 0; i < ARRAY_SIZE(cookies->keys); i++) {
        net_str_t *k = &cookies->keys[i], *v = &cookies->values[i];

        s = net_skip(s, end, "=", k);
        s = net_skip(s, end, "; ", v);

        if(k->len == 0 || v->len == 0) {
            k->p = v->p = NULL;
            k->len = v->len = 0;
            break;
        }
    }

    return s;
}

int net_vcmp(const net_str_t *str1, const char *str2) {
    size_t n2 = strlen(str2), n1 = str1->len;
    int r = memcmp(str1->p, str2, (n1 < n2) ? n1 : n2);
    if(r == 0) {
        return n1 - n2;
    }
    return r;
}


net_str_t *net_get_http_cookie(http_pairs_t *cookies, const char *name) {
    size_t i;

    for(i = 0; i < ARRAY_SIZE(cookies->keys); i++) {
        net_str_t *k = &cookies->keys[i], *v = &cookies->values[i];
        if(k->p != NULL && !net_vcmp(k, name))
            return v;
    }

    return NULL;
}

const char *net_parse_http_query_string(const char *s, const char *end, http_pairs_t *query) {
    size_t i;

    bzero(query, sizeof(*query));

    for(i = 0; i < ARRAY_SIZE(query->keys); i++) {
        net_str_t *k = &query->keys[i], *v = &query->values[i];

        s = net_skip(s, end, "=", k);
        s = net_skip(s, end, "&", v);

        if(k->len == 0 || v->len == 0) {
            k->p = v->p = NULL;
            k->len = v->len = 0;
            break;
        }
    }

    return s;
}

net_str_t *net_get_http_query_string(http_pairs_t *query, const char *name) {
    size_t i;

    for(i = 0; i < ARRAY_SIZE(query->keys); i++) {
        net_str_t *k = &query->keys[i], *v = &query->values[i];
        if(k->p != NULL && !net_vcmp(k, name))
            return v;
    }

    return NULL;
}

