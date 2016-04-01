/******************************************************************************
  文 件 名   : csha1.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2015年12月14日
  功能描述   : csha1.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2015年12月14日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __csha1_h
#define __csha1_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#include <stdint.h>


struct csha1_ctx_s {
    uint32_t h0, h1, h2, h3, h4;
	uint64_t length;
    unsigned char buf[64];
    unsigned int buf_len;
};

typedef struct csha1_ctx_s csha1_ctx_t;

extern void csha1_final(csha1_ctx_t *ctx, char digest[41]);
extern void csha1_init(csha1_ctx_t *ctx);
extern void csha1_update(csha1_ctx_t *ctx, char *data, unsigned int data_size);
extern char *csha1_hash(char digest[41], ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __csha1_h */
