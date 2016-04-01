/******************************************************************************
  文 件 名   : cbin.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2015年4月4日
  功能描述   : cbin.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2015年4月4日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __cbin_h
#define __cbin_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern void cbin_bin_to_hex(const unsigned char *bin, unsigned char *hex, int size);
extern void cbin_hex_to_bin(const unsigned char *hex, unsigned char *bin, int size);
extern void cbin_bcd_to_asc(const unsigned char *bcd, unsigned char *asc, int size);
extern void cbin_asc_to_bcd(const unsigned char *asc, unsigned char *bcd, int size);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __cbin_h */
