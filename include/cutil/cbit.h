/******************************************************************************
  文 件 名   : cbit.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2015年3月31日
  功能描述   : cbit.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2015年3月31日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __cbit_h
#define __cbit_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern int cbit_get(const unsigned char *bits, int pos);
extern void cbit_rot_left(unsigned char *bits, int size, int count);
extern void cbit_rot_right(unsigned char *bits, int size, int count);
extern void cbit_set(unsigned char *bits, int pos, int state);
extern void cbit_xor(const unsigned char *bits1, const unsigned char *bits2,
                       unsigned char *bitsx, int size);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __cbit_h */
