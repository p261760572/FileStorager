/******************************************************************************
  文 件 名   : carray.h
  版 本 号   : 初稿
  作    者   : xjb(beymy.en@gmail.com)
  生成日期   : 2014年2月25日
  功能描述   : carray.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年2月25日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __carray_h
#define __carray_h


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CARRAY_DEFAULT_SIZE 32

struct carray_s
{
    void **array;
    int size;
    int capacity;
    void (*free_fn)(void *data);
};

typedef struct carray_s carray_t;

extern int carray_init(carray_t *arr, void (*free_fn)(void *data));
extern void carray_destory(carray_t *arr);
extern carray_t *carray_new(void (*free_fn)(void *data));
extern void carray_free(carray_t *arr);
extern void *carray_get(carray_t *arr, int idx);
extern int carray_insert(carray_t *arr, int idx, void *data);
extern int carray_append(carray_t *arr, void *data);
extern int carray_remove(carray_t *arr, int idx, void **data);
extern int carray_size(carray_t *arr);
extern void carray_sort(carray_t *arr, int(*sort_fn)(const void *key1, const void *key2));

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __carray_h */
