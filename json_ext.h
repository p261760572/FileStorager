/******************************************************************************
  文 件 名   : json_ext.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年12月3日
  功能描述   : json_ext.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年12月3日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __json_ext_h
#define __json_ext_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern json_object* json_util_object_from_file(const char *filename, const char *fromcode, const char *tocode);
extern json_object *json_util_object_get(json_object *obj, const char *key);
extern int json_util_object_get_int(json_object* obj, const char *key);
extern const char *json_util_object_get_string(json_object* obj, const char *key);
extern int json_util_object_to_file(const char *filename, struct json_object *obj, const char *fromcode, const char *tocode);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __json_ext_h */
