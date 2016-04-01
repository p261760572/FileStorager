/******************************************************************************
  文 件 名   : rsa.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2015年12月22日
  功能描述   : rsa.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2015年12月22日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __crsa_h
#define __crsa_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern cbig_num_t crsa_encrypt(cbig_num_t plaintext, cbig_num_t e, cbig_num_t n);
extern  cbig_num_t crsa_decrypt(cbig_num_t ciphertext, cbig_num_t d, cbig_num_t n);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __crsa_h */
