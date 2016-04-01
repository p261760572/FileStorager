/******************************************************************************
  文 件 名   : clog.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年11月14日
  功能描述   : clog.c的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年11月14日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __clog_h
#define __clog_h

#define MAX_TIME_STR_LEN 20
#define MAX_OPTIONS 100
#define MAX_PATH_LEN 1024
#define CLOG_BUF_MIN_SIZE 1024
#define CLOG_BUF_MAX_SIZE 1024*1024

#define clog_debug(log, ...) \
    clog_printf(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_DEBUG, __VA_ARGS__)

#define clog_info(log, ...) \
    clog_printf(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_INFO, __VA_ARGS__)

#define clog_notice(log, ...) \
    clog_printf(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_NOTICE, __VA_ARGS__)

#define clog_warn(log, ...) \
    clog_printf(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_WARN, __VA_ARGS__)

#define clog_error(log, ...) \
    clog_printf(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_ERROR, __VA_ARGS__)

#define clog_fatal(log, ...) \
    clog_printf(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_FATAL, __VA_ARGS__)

#define clog_debug_hex(log, buf, len) \
    clog_printf_hex(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_DEBUG, buf, len)

#define clog_info_hex(log, buf, len) \
    clog_printf_hex(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_INFO, buf, len)

#define clog_notice_hex(log, buf, len) \
    clog_printf_hex(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_NOTICE, buf, len)

#define clog_warn_hex(log, buf, len) \
    clog_printf_hex(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_WARN, buf, len)

#define clog_error_hex(log, buf, len) \
    clog_printf_hex(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_ERROR, buf, len)

#define clog_fatal_hex(log, buf, len) \
    clog_printf_hex(log, __FILE__, sizeof(__FILE__)-1, __FUNCTION__, sizeof(__FUNCTION__)-1, __LINE__, \
    CLOG_LEVEL_FATAL, buf, len)



//日志等级
typedef enum
{
    CLOG_LEVEL_DEBUG,
    CLOG_LEVEL_INFO,
    CLOG_LEVEL_NOTICE,
    CLOG_LEVEL_WARN,
    CLOG_LEVEL_ERROR,
    CLOG_LEVEL_FATAL
} clog_level;


struct clog_s
{
    char file[MAX_PATH_LEN+1];
    int level;
    char log_file[MAX_PATH_LEN+1];
	size_t max_size;
};

typedef struct clog_s clog_t;

#define log_debug(...) clog_debug(clog_get(), __VA_ARGS__)
#define log_info(...) clog_info(clog_get(), __VA_ARGS__)
#define log_notice(...) clog_notice(clog_get(), __VA_ARGS__)
#define log_warn(...) clog_warn(clog_get(), __VA_ARGS__)
#define log_error(...) clog_error(clog_get(), __VA_ARGS__)
#define log_fatal(...) clog_fatal(clog_get(), __VA_ARGS__)
#define log_debug_hex(buf, len) clog_debug_hex(clog_get(), buf, len)
#define log_info_hex(buf, len) clog_info_hex(clog_get(), buf, len)
#define log_notice_hex(buf, len) clog_notice_hex(clog_get(), buf, len)
#define log_warn_hex(buf, len) clog_warn_hex(clog_get(), buf, len)
#define log_error_hex(buf, len) clog_error_hex(clog_get(), buf, len)
#define log_fatal_hex(buf, len) clog_fatal_hex(clog_get(), buf, len)


extern clog_t *clog_new(const char *conf_file);
extern void clog_destroy(clog_t *log);
extern void clog_free(clog_t *log);
extern int clog_init(clog_t *log, const char *conf_file);
extern void clog_printf(clog_t * log, const char *file, size_t file_len,
                          const char *fun, size_t fun_len, long line,
                          const int level, const char *format, ...);
extern void clog_printf_hex(clog_t * log, const char *file, size_t file_len,
                              const char *fun, size_t fun_len, long line,
                              const int level, const char *str, size_t len);
extern const char *clog_set_option(clog_t *log, const char *name, const char *value);
extern void clog_set(clog_t *log);
extern clog_t *clog_get();



#endif //__clog_h

