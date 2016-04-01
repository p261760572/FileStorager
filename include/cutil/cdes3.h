/******************************************************************************
  文 件 名   : cdes3.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2015年11月16日
  功能描述   : cdes3.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2015年11月16日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __c3des_h
#define __c3des_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern void cdes3_cbc_decrypt(const unsigned char *ciphertext, unsigned char *plaintext,
                           const unsigned char *key, int size);
extern void cdes3_cbc_encrypt(const unsigned char *plaintext, unsigned char *ciphertext,
                               const unsigned char *key, int size);
extern void cdes3_decrypt(const unsigned char *ciphertext, unsigned char *plaintext,
                                  const unsigned char *key);
extern void cdes3_ecb_decrypt(const unsigned char *ciphertext, unsigned char *plaintext,
                           const unsigned char *key, int size);
extern void cdes3_ecb_encrypt(const unsigned char *plaintext, unsigned char *ciphertext,
                               const unsigned char *key, int size);
extern void cdes3_encrypt(const unsigned char *plaintext, unsigned char *ciphertext,
                                  const unsigned char *key);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __c3des_h */
