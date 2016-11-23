/******************************************************************************
  文 件 名   : crc32.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2016年11月23日
  功能描述   : crc32.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2016年11月23日
    作    者   : xjb
    修改内容   : 创建文件

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
