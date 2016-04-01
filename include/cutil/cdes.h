/******************************************************************************
  文 件 名   : cdes.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2015年4月3日
  功能描述   : cdes.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2015年4月3日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __cdes_h
#define __cdes_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern void cdes_cbc_decrypt(const unsigned char *ciphertext, unsigned char *plaintext,
                           const unsigned char *key, int size);
extern void cdes_cbc_encrypt(const unsigned char *plaintext, unsigned char *ciphertext,
                               const unsigned char *key, int size);
extern void cdes_decrypt(const unsigned char *ciphertext, unsigned char *plaintext,
                                  const unsigned char *key);
extern void cdes_ecb_decrypt(const unsigned char *ciphertext, unsigned char *plaintext,
                           const unsigned char *key, int size);
extern void cdes_ecb_encrypt(const unsigned char *plaintext, unsigned char *ciphertext,
                               const unsigned char *key, int size);
extern void cdes_encrypt(const unsigned char *plaintext, unsigned char *ciphertext,
                                  const unsigned char *key);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __cdes_h */
