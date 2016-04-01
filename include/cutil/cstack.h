/******************************************************************************
  文 件 名   : cstack.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年10月17日
  功能描述   : cstack.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年10月17日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __cstack_h
#define __cstack_h

#include "clist.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef clist_t cstack_t;

#define cstack_init clist_init

#define cstack_destroy clist_destroy

#define cstack_new clist_new

#define cstack_free clist_free

int cstack_push(cstack_t *stack, void *data);

int cstack_pop(cstack_t *stack, void **data);

#define cstack_peek(stack) (clist_head(stack) == NULL ? NULL : clist_data(clist_head(stack)))

#define cstack_size clist_size


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __cstack_h */
