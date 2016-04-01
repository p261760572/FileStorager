/******************************************************************************
  文 件 名   : chash.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年10月17日
  功能描述   : chash.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年10月17日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __chash_h
#define __chash_h

#include "clist.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CHASH_LOAD_FACTOR 0.75

struct chash_s
{
    int buckets;
    int (*hash_fn)(void *key);
    int (*equal_fn)(void *key1, void *key2);
    void (*free_fn)(void *data);
    int size;
    clist_t *table;
};

typedef struct chash_s chash_t;


struct chash_kstr_s
{
    chash_t htbl;
    void (*free_fn)(void *data);
};

typedef struct chash_kstr_s chash_kstr_t;


struct chash_kstr_entry_s
{
	char *k;
	void *v;
	chash_kstr_t *htbl;
};

typedef struct chash_kstr_entry_s chash_kstr_entry_t;


extern void chash_destroy(chash_t *htbl);
extern int chash_init(chash_t *htbl, int buckets, int (*hash_fn)(void *key),
				   int (*equal_fn)(void *key1, void *key2), void (*free_fn)(void *data));
extern int chash_insert(chash_t *htbl, void *data);
extern void chash_kstr_destroy(chash_kstr_t *htbl);
extern int chash_kstr_init(chash_kstr_t *htbl, int buckets, void (*free_fn)(void *data));
extern int chash_kstr_insert(chash_kstr_t *htbl, char *key, void *data);
extern int chash_kstr_lookup(const chash_kstr_t *htbl, char *key, void **data);
extern int chash_kstr_remove(chash_kstr_t *htbl, char *key, void **data);
extern int chash_lookup(const chash_t *htbl, void **data);
extern int chash_remove(chash_t *htbl, void **data);

#define chash_size(htbl) ((htbl)->size)


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __chash_h */
