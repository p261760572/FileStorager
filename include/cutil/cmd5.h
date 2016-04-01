/******************************************************************************
  文 件 名   : cmd5.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2015年6月9日
  功能描述   : cmd5.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2015年6月9日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __cmd5_h
#define __cmd5_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

typedef struct cmd5_ctx_s {
    unsigned int buf[4];
    unsigned int bits[2];
    unsigned char in[64];
} cmd5_ctx_t;

extern void cmd5_init(cmd5_ctx_t * ctx);
extern void cmd5_update(cmd5_ctx_t * ctx,unsigned char * buf,unsigned int len);
extern void cmd5_digest(cmd5_ctx_t * ctx, unsigned char digest[16]);
extern void cmd5_hexdigest(cmd5_ctx_t * ctx, unsigned char buf[33]);
extern unsigned char *cmd5_hash(unsigned char buf[33], ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __cmd5_h */
