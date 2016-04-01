/******************************************************************************
  文 件 名   : action_handler.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2014年10月23日
  功能描述   : action_handler.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2014年10月23日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __action_handler_h
#define __action_handler_h

#include "base.h"
#include "json.h"
#include "ocilib.h"


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */

#define MAX_JSON_DEEP 3
#define DEFAULT_SQL_SIZE 1024
#define MAX_SQL_SIZE 8192
#define MAX_OUT_VARCHAR_SIZE 512
#define MAX_OUT_SIZE 4
#define MAX_ERR_MSG_SIZE 512
#define MAX_BUFFER_SIZE 4096
#define MAX_FUN_CONFIG_SIZE 4096
#define MAX_FUN_INFO_SIZE 1024
#define DEFAULT_BUFFER_SIZE 1024

#define TEST_DATABSE_SQL "select 1 from dual"


struct session_attr_s
{
	char session_flag;
	char captcha[6+1];
	char img_captcha[6+1];
	char userid[38+1];
	char login_name[32+1];
	char inst_id[8+1];
	char user_level[1+1];
	char login_type[1+1];
	char province[2+1];
	char city[2+1];
	char district[2+1];
	char attr1[11+1];
	char attr2[11+1];
	char attr3[11+1];
	char attr4[11+1];
	char attr5[11+1];
};

typedef struct session_attr_s session_attr_t;


struct process_ctx_s
{
    shm_data *shm;
    session *session;
	char action[128+1];
    char ip[15+1];
	//int code;
	const char *sign;
	const char *body;
	int body_len;
	void *user_data1;
    //session_attr_t attr;
    char *headers;
	int headers_size;
	oci_connection_t *con;
	char op[1+1];
	char log_flag[1+1];
	char log_id[28+1];
};

typedef struct process_ctx_s process_ctx_t;

typedef int (*fetch_caller)(void *ctx, oci_resultset_t *rs, int rownum);

extern int captcha_handler(process_ctx_t *ctx, connection *con, int *flag, char *outbuf, int outsize);
extern void action_handler(process_ctx_t *ctx, json_object *request, json_object *response);
extern int gen_uuid(unsigned char buf[33]);
extern int check_function_acl(process_ctx_t *ctx);
extern int check_session(process_ctx_t *ctx);
extern int load_fun_config(oci_connection_t *con);
extern int sql_execute(oci_connection_t *con, char *sql, carray_t *bind, fetch_caller fetch, void *ctx, char *err, size_t err_size);
extern void db_errmsg_trans(char *err_msg, size_t err_size);
extern int select_fetch_count_handler(void *ctx, oci_resultset_t *rs, int rownum);
extern int select_fetch_rows_handler(void *ctx, oci_resultset_t *rs, int rownum);
extern int select_fetch_row_handler(void *ctx, oci_resultset_t *rs, int rownum);
extern int select_fetch_total_handler(void *ctx, oci_resultset_t *rs, int rownum);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __action_handler_h */
