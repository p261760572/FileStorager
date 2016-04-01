/******************************************************************************
  文 件 名   : cbuf.h
  版 本 号   : 初稿
  作    者   : xjb(beymy.en@gmail.com)
  生成日期   : 2014年2月27日
  功能描述   : cbuf.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年2月27日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/


#ifndef __cbuf_h
#define __cbuf_h

#include <stdio.h>

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

struct cbuf_s
{
    char *start; /**<  缓冲的开始位置 */
    char *pos; /**<  缓冲当前读写位置 */
    char *end; /**<  缓冲的结束位置+1 */

    size_t size_min; /**<  缓冲的最小大小 */
    size_t size_max; /**<  缓冲的最大大小,0表示无限制 */
    size_t size_real; /**<  缓冲的实际大小 */
};

typedef struct cbuf_s cbuf_t;

extern int cbuf_append(cbuf_t * buf, const char *str, size_t len);
extern int cbuf_remove(cbuf_t * buf, size_t n);
extern void cbuf_destroy(cbuf_t * buf);
extern void cbuf_free(cbuf_t * buf);
extern int cbuf_init(cbuf_t *buf, size_t min, size_t max);
extern cbuf_t *cbuf_new(size_t min, size_t max);
extern int cbuf_vprintf(cbuf_t * buf, const char *format, va_list args);
extern int cbuf_printf(cbuf_t * buf, const char *format, ...);
extern int cbuf_printf_hex(cbuf_t * buf, const char *str, size_t len);
extern void cbuf_reset(cbuf_t *buf);

#define cbuf_len(buf) ((buf)->pos - (buf)->start)
#define cbuf_str(buf) ((buf)->start)

#ifdef __cplusplus
}
#endif /* __cplusplus */



#endif //__cbuf_h

