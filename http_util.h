/******************************************************************************
  文 件 名   : http_util.h
  版 本 号   : 初稿
  作    者   : xiongbin
  生成日期   : 2016年3月29日
  功能描述   : http_util.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2016年3月29日
    作    者   : xiongbin
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __http_util_h
#define __http_util_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */


#define INT64_FMT PRId64

#ifndef NET_MALLOC
#define NET_MALLOC malloc
#endif

#ifndef NET_FREE
#define NET_FREE free
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#endif

#ifndef MAX_HTTP_PAIRS
#define MAX_HTTP_PAIRS 20
#endif


struct net_str_s {
    const char *p;
    size_t len;
};

typedef struct net_str_s net_str_t;

struct http_pairs_s {
    net_str_t keys[MAX_HTTP_PAIRS];
    net_str_t values[MAX_HTTP_PAIRS];
};

typedef struct http_pairs_s http_pairs_t;


extern net_str_t *net_get_http_cookie(http_pairs_t *cookies, const char *name);
extern net_str_t *net_get_http_query_string(http_pairs_t *query, const char *name);
extern const char *net_parse_http_cookies(const char *s, const char *end, http_pairs_t *cookies);
extern const char *net_parse_http_query_string(const char *s, const char *end, http_pairs_t *query);
extern int net_send_http_file2(struct stat *st, const char *range_header, const char *custom_headers, char *outbuf, int outsize, int64_t *offset, int64_t *len);
extern const char *net_skip(const char *s, const char *end, const char *delims,
                              net_str_t *v);
extern int net_vcmp(const net_str_t *str1, const char *str2);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __http_util_h */
