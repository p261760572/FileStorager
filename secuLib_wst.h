/******************************************************************************
  �� �� ��   : secuLib_wst.h
  �� �� ��   : ����
  ��    ��   : xiongbin
  ��������   : 2016��5��23��
  ��������   : secuLib_wst.c ��ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2016��5��23��
    ��    ��   : xiongbin
    �޸�����   : �����ļ�

*****************************************************************************/

#ifndef __seculib_wst_h
#define __seculib_wst_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern int DES_TO_MD5(char *return_code, char *sek_index, char *key, int in_length, char *in_data, int *out_length, char *out_data);
extern int DES_TO_RSA_KEY(char *return_code, char *sek_index, char *key, int rsa_length, char *rsa_key, int *out_length, char *out_data);
extern int GET_TMK(char *return_code, char *sek_index, char *tek_index, unsigned char flag, char *sek_tmk_data, char *tek_tmk_data, char *chk_tmk_data);
extern int GET_WORK_KEY(char *return_code, char *sek_index1, char *sek_index2, char *tmk, unsigned char tmk_flag, unsigned char pm_flag, char *sek_pikmak_data, char *tmk_pikmak_data, char *CheckValue);
extern int DES3(char *return_code, char *sek_index, char *key, int in_length, char *in_data, int *out_length, char *out_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __seculib_wst_h */
