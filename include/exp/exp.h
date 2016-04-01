/******************************************************************************
  文 件 名   : exp.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年10月19日
  功能描述   : exp.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年10月19日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __exp_h
#define __exp_h

#include "carray.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct chash_entry_int_s
{
    char *k;
    int v;
};

typedef struct chash_entry_int_s chash_entry_int_t;


struct exp_context_s
{
    void *data;
    char *(*get)(void *data, const char *name);
};

typedef struct exp_context_s exp_context_t;

struct exp_item_s
{
    void *value;
    int type;
};

typedef struct exp_item_s exp_item_t;


#define MAX_KEYWORD_SIZE 32

extern void exp_destroy();
extern int exp_init();
extern int test_exp(exp_context_t *context, char *expression);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __exp_h */
