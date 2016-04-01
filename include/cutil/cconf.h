/******************************************************************************
  文 件 名   : conf.h
  版 本 号   : 初稿
  作    者   : xjb(beymy.en@gmail.com)
  生成日期   : 2014年2月23日
  功能描述   : conf.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年2月23日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __conf_h
#define __conf_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#define CCONF_LINE_SIZE 1024

typedef int (*config_option_handler)(void *,const char *, const char *);


/**
*解析配置文件
*@return 成功返回0,出错返回-1
*/
extern int config_parse_file(char *filename, void *data, config_option_handler handler);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __conf_h */
