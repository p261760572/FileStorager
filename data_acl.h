/******************************************************************************
  文 件 名   : data_acl.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2015年3月30日
  功能描述   : data_acl.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2015年3月30日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __data_acl_h
#define __data_acl_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern int gen_data_acl(sql_ctx_t *ctx, char *res_code, char *alias, cbuf_t *buf);
extern int load_data_rule();

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __data_acl_h */
