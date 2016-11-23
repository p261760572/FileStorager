/******************************************************************************
  �� �� ��   : crc32.h
  �� �� ��   : ����
  ��    ��   : xjb
  ��������   : 2016��11��23��
  ��������   : crc32.c ��ͷ�ļ�
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2016��11��23��
    ��    ��   : xjb
    �޸�����   : �����ļ�

*****************************************************************************/

#ifndef CRC32_H_
#define CRC32_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

extern uint32_t crc32(uint32_t crc, const void *buf, size_t size);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* CRC32_H_ */
