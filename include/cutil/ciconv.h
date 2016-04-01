/******************************************************************************
  文 件 名   : ciconv.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年12月3日
  功能描述   : ciconv.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年12月3日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __ciconv_h
#define __ciconv_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern int code_convert(const char *fromcode, const char *tocode, char *inbuf, size_t inlen, char *outbuf, size_t outlen);
extern int gbk_to_utf8(char *inbuf, size_t inlen, char *outbuf, size_t outlen);
extern int utf8_to_gbk(char *inbuf, size_t inlen, char *outbuf, size_t outlen);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __ciconv_h */
