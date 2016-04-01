/******************************************************************************
  文 件 名   : cdate.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年11月14日
  功能描述   : cdate.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年11月14日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __cdate_h
#define __cdate_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern struct tm cdate_now();
extern void cdate_now_date(char *buf, size_t buf_size);
extern void cdate_now_datetime(char *buf, size_t buf_size);
extern void cdate_strftime(struct tm *t, char *format, char *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __cdate_h */
