/******************************************************************************
  文 件 名   : cfile.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年10月17日
  功能描述   : cfile.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年10月17日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __cfile_h
#define __cfile_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#define CFILE_MAX_PATH 1024

#define CFILE_DEFAULT_DIR_MODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define CFILE_DEFAULT_FILE_MODE (S_IRWXU | S_IRGRP | S_IROTH)

extern int cfile_mkdirs(const char *dir, mode_t mode);
extern char *cfile_get_filename(char *path);
extern char *cfile_get_suffix(char *filename);
extern int cfile_create(char *path);
extern int cfile_copy(char *source_path, char *dest_path);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __cfile_h */
