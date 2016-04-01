/******************************************************************************
  文 件 名   : gen_sql.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年11月7日
  功能描述   : gen_sql.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年11月7日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __gen_sql_h
#define __gen_sql_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern int gen_sql(char *sql, cbuf_t *sqlbuf, carray_t *bind);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __gen_sql_h */
