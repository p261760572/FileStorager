#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <uuid/uuid.h>

#include "ibdcs.h"
#include "base.h"
#include "frame.h"
#include "md5.h"

#include "libxl.h"

#include "json.h"
#include "json_ext.h"

#include "cdefs.h"
#include "cstr.h"
#include "cbuf.h"
#include "carray.h"
#include "cfile.h"
#include "cdate.h"
#include "cbin.h"
#include "cdes.h"
#include "cmd5.h"

#include "ocilib.h"
#include "exp.h"
#include "sql.h"

#include "gen_sql.h"
#include "data_acl.h"
#include "action_handler.h"
#include "secuLib_wst.h"
#include "parafile.h"
#include "ini_parser.h"

extern void send_file2(int fd, int *flag, const char *path, long offset, long file_size);

#define SELECT_TOTAL "select count(1) total"
//#define SELECT_PAGE_START "select * from (select rownum rn, a.* from ("
//#define SELECT_PAGE_END ") a where rownum <= :b%d*:b%d) where rn > (:b%d-1)*:b%d"

#define SELECT_PAGE_START "select * from (select rownum rn, a.* from ("
#define SELECT_PAGE_END ") a) where rn <= :b%d*:b%d and rn > (:b%d-1)*:b%d"


//#define SELECT_PAGE_START "select a.* from("
//#define SELECT_PAGE_END ") a where rn_ > (:b%d-1)*:b%d and rn_ <= :b%d*:b%d"


struct fun_config_s {
    char url[256+1];
    char module_name[128+1];
    char param_list[512+1];
    char exec_type[1+1];
    char input[32+1];
    char test[128+1];
};

typedef struct fun_config_s fun_config_t;

struct fun_info_s {
    char url[256+1];
    char op[1+1];
    char log_flag[1+1];
};

typedef struct fun_info_s fun_info_t;


typedef int (*module_fn)(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size);


struct execute_module {
    char *module_name;
    module_fn fn;
};

int execute_config(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size);


extern char *document_root;

fun_info_t g_fun_info[MAX_FUN_INFO_SIZE];
int g_fun_info_len = 0;


fun_config_t g_fun_config[MAX_FUN_CONFIG_SIZE];
int g_fun_config_len = 0;





#if 0
static const char *json_util_array_get_string(json_object* obj, int idx) {
    json_object *result = json_object_array_get_idx(obj, idx);
    return json_object_get_string(result);
}
#endif


/*
static int json_util_copy(json_object *from, json_object *to, char *key, char *dest, char *new_key) {
    int ret = 0;
    json_object *key_obj = NULL, *dest_obj = NULL;
    char key_copy[DEFAULT_BUFFER_SIZE], dest_copy[DEFAULT_BUFFER_SIZE];
    char *key_array[MAX_JSON_DEEP], *dest_array[MAX_JSON_DEEP];
    int key_len = 0, dest_len = 0, i;

    cstr_copy(key_copy, key, sizeof(key_copy));
    key_len = cstr_split(key_copy, ".", key_array, ARRAY_SIZE(key_array));

    for(i = 0; i < key_len; i ++) {
        json_object_object_get_ex(from, key_array[i], &key_obj);
        if(key_obj == NULL)
            break;
        from = key_obj;
    }

    dest_obj = to; // to为默认dest
    if(!cstr_empty(dest)) {
        cstr_copy(dest_copy, dest, sizeof(dest));
        dest_len = cstr_split(dest_copy, ".", dest_array, ARRAY_SIZE(dest_array));

        for(i = 0; i < dest_len; i ++) {
            json_object_object_get_ex(to, dest_array[i], &dest_obj);
            if(key_obj == NULL)
                break;
            to = dest_obj;
        }
    }

    if(key_obj == NULL || dest_obj == NULL) {
        ret = -1;
    } else {
        if(json_object_get_type(dest_obj) == json_type_object) {
            json_object_object_add(dest_obj, new_key, key_obj);
            json_object_get(key_obj);
        } else if(json_object_get_type(dest_obj) == json_type_array) {
            int len = json_object_array_length(dest_obj);
            for(i = 0; i < len; i ++) {
                json_object *temp = json_object_array_get_idx(dest_obj, i);
                if(json_object_get_type(temp) != json_type_object) {
                    ret = -1;
                    break;
                } else {
                    json_object_object_add(temp, new_key, key_obj);
                    json_object_get(key_obj);
                }
            }
        }
    }

    return ret;
}
*/


/*
static json_object *json_util_get(json_object *obj, char *key) {
    int ret = 0;
    json_object *key_obj = NULL;
    char key_copy[DEFAULT_BUFFER_SIZE];
    char *key_array[MAX_JSON_DEEP];
    int key_len = 0, i;

    cstr_copy(key_copy, key, sizeof(key_copy));
    key_len = cstr_split(key_copy, ".", key_array, ARRAY_SIZE(key_array));

    for(i = 0; i < key_len; i ++) {
        json_object_object_get_ex(from, key_array[i], &key_obj);
        if(key_obj == NULL)
            break;
    }



    return ret;
}
*/


char *get_current_value(void *data, const char *name) {
    process_ctx_t *ctx = (process_ctx_t *)data;


    if(strcmp(name, "CurrentAction") == 0) {
        return ctx->action;
    } else if(strcmp(name, "CurrentLogId") == 0) {
        return ctx->log_id;
    } else if(ctx->session == NULL) {
        return NULL;
    } else {
        session_attr_t *attr = (session_attr_t *)ctx->session->remark;
        if(strcmp(name, "CurrentAttr1") == 0) {
            return attr->attr1;
        } else if(strcmp(name, "CurrentAttr2") == 0) {
            return attr->attr2;
        } else if(strcmp(name, "CurrentAttr3") == 0) {
            return attr->attr3;
        }
    }

    return NULL;
}


char *get_value(void *data, const char *name) {
    void **param = (void **)data;
    process_ctx_t *ctx = param[0];
    json_object *obj = param[1];


    //dcs_debug(0, 0, "at %s(%s:%d) [%s]",__FUNCTION__,__FILE__,__LINE__, name);

    if(strncmp(name, "Current", 7) == 0) {
        return get_current_value(ctx, name);
    }
    //dcs_debug(0, 0, "at %s(%s:%d) [%s]",__FUNCTION__,__FILE__,__LINE__, name);
    return (char *)json_util_object_get_string(obj, name);
}

oci_connection_t *get_connection(void *data) {
    process_ctx_t *ctx = (process_ctx_t *)data;
    return ctx->con;
}

static void print_bind(carray_t *bind) {
    int i, len;
    char *p;
    if(bind != NULL) {
        len = carray_size(bind);
        for(i = 0; i < len; i ++) {
            p = (char *)carray_get(bind, i);
            if(p) {
                dcs_debug(0, 0, "[%s]", p);
            } else {
                dcs_debug(0, 0, "[NULL]");
            }
        }
    }
}


int select_fetch_rows_handler(void *ctx, oci_resultset_t *rs, int rownum) {

    void **params = (void **)ctx;
    int rowcount = *((int *)params[0]), i;
    json_object *rows = (json_object *)params[1], *row;
    const char *value;

    if(rownum > rowcount) {
        return 0; //限制
    }

    row = json_object_new_object();
    for(i = 1; i <= oci_get_column_count(rs); i ++) {
        value = oci_get_string(rs, i);
        value = (value == NULL ? "" : value);
        json_object_object_add(row, oci_get_column_name(rs, i), json_object_new_string(value));
    }
    json_object_array_add(rows, row);
    return 1;
}


int select_fetch_row_handler(void *ctx, oci_resultset_t *rs, int rownum) {
    int i;
    const char *value;
    json_object *row = (json_object *)ctx;
    for(i = 1; i <= oci_get_column_count(rs); i ++) {
        value = oci_get_string(rs, i);
        value = (value == NULL ? "" : value);
        json_object_object_add(row, oci_get_column_name(rs, i), json_object_new_string(value));
    }
    return 0;
}

int select_fetch_total_handler(void *ctx, oci_resultset_t *rs, int rownum) {
    json_object *row = (json_object *)ctx;
    json_object_object_add(row, oci_get_column_name(rs, 1), json_object_new_int(oci_get_int(rs, 1)));
    return 0; //终止fetch
}

int select_fetch_count_handler(void *ctx, oci_resultset_t *rs, int rownum) {
    int *count = (int *)ctx;

    *count = oci_get_int(rs, 1);

    return 0;
}


int select_fetch_column_handler(void *ctx, oci_resultset_t *rs, int rownum) {

    void **params = (void **)ctx;
    int rowcount = *((int *)params[0]);
    json_object *rows = (json_object *)params[1];
    const char *value;

    if(rownum > rowcount) {
        return 0; //限制
    }

    value = oci_get_string(rs, 1);
    value = (value == NULL ? "" : value);

    json_object_array_add(rows, json_object_new_string(value));
    return 1;
}


static int select_fetch_export_txt_handler(void *ctx, oci_resultset_t *rs, int rownum) {
    int i;
    const char *value;
    void **arr = (void **)ctx;
    int fd= *((int *)arr[0]);
    char *delim = (char *)arr[1];

    char line[MAX_BUFFER_SIZE];
    size_t line_size = sizeof(line);
    int len = 0;

    bzero(line, sizeof(line));
    for(i = 1; i <= oci_get_column_count(rs); i ++) {
        value = oci_get_string(rs, i);
        value = (value == NULL ? "" : value);
        if(i == 1) {
            len += snprintf(line + len, line_size-len, "%s", value);
        } else {
            len += snprintf(line + len, line_size-len, "%s%s", delim, value);
        }
    }

    len += snprintf(line + len, line_size-len, "\r\n");

    if(write(fd, line, len) < 0) {
        dcs_log(0, 0, "at %s(%s:%d) error write[%d] %s",__FUNCTION__,__FILE__,__LINE__,fd,strerror(errno));
        return -1;
    }

    return 1;
}

static int select_fetch_export_xls_handler(void *ctx, oci_resultset_t *rs, int rownum) {
    int i;
    void **arr = (void **)ctx;
    SheetHandle sheet= (SheetHandle)arr[0];
    int row= *((int *)arr[1]);
    int col= *((int *)arr[2]);
    const char *value;

    for(i = 1; i <= oci_get_column_count(rs); i ++) {
        if(oci_get_column_type(rs, i) == OCI_CDT_NUMERIC) {
            xlSheetWriteNumA(sheet, row + rownum-1, col + i - 1, oci_get_double(rs, i), 0);
        } else {
            value = oci_get_string(rs, i);
            xlSheetWriteStrA(sheet, row + rownum - 1, col + i - 1, (value == NULL ? "" : value), 0);
        }
    }

    return 1;
}


int gen_uuid(unsigned char buf[33]) {
    static unsigned char hex[] = "0123456789abcdef";

    unsigned char *pbuf = buf;

    uuid_t uuid;
    uuid_generate(uuid);

    unsigned char *p = uuid;
    int i;
    for(i = 0; i < sizeof(uuid_t); i++, p++) {
        *(pbuf)++ = hex[(p[0] >> 4) & 0xf];
        *(pbuf)++ = hex[p[0] & 0xf];
    }
    *pbuf = '\0';

    return 0;
}

void db_errmsg_trans(char *err_msg, size_t err_size) {
    if(strncmp(err_msg, "ORA-20999: ", 11) == 0) {
        char *p = strchr(err_msg, '\n');
        if(p) {
            *p = '\0';
        }
        memmove(err_msg, err_msg+11, err_size - 11);
    }
}


/**
*加载功能配置
*@param con 数据库连接
*@param sql 要执行的SQL
*@param bind 绑定变量数组
*@param fetch fetch数据的回调函数,rownum从1开始
*@param ctx fetch函数的上下文
*@param err 错误信息buf
*@param err_size 错误信息buf大小
*
*@return 成功返回影响的记录数,失败返回-1
*/
int sql_execute(oci_connection_t *con, char *sql, carray_t *bind, fetch_caller fetch, void *ctx, char *err_msg, size_t err_size) {
    boolean res = FALSE;
    int count = -1, i, code;
    void *value;
    oci_error_t *oci_err = NULL;

    if(strcmp(sql, TEST_DATABSE_SQL) != 0) {
        cbuf_t buf;
        cbuf_init(&buf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
        gen_sql(sql, &buf, bind);
        dcs_debug(0, 0, "at %s(%s:%d) SQL\n%s",__FUNCTION__,__FILE__,__LINE__,cbuf_str(&buf));
        cbuf_destroy(&buf);
    }

    oci_statement_t *stmt = oci_statement_new(con);
    if(stmt == NULL) {
        oci_err = oci_get_last_error();
    } else {
        if(oci_prepare(stmt, sql) != TRUE) {
            oci_err = oci_get_last_error();
        } else {
            for(i = 1; i <= oci_get_bind_count(stmt); i++) {
                if(i > carray_size(bind)) {
                    oci_bind_string_by_pos(stmt, i, "");
                } else if((value = carray_get(bind, i-1)) == NULL) {
                    oci_bind_string_by_pos(stmt, i, "");
                } else {
                    oci_bind_string_by_pos(stmt, i, value);
                }
            }

            if(oci_execute(stmt) != TRUE) {
                oci_err = oci_get_last_error();
            } else {
                res = TRUE;
                if(oci_get_stmt_type(stmt) == OCI_ST_SELECT) {
                    oci_resultset_t *rs = oci_get_resultset(stmt);
                    int fetch_break = 0;
                    for(i = 1; oci_fetch_next(rs); i ++) {
                        if(fetch != NULL) {
                            int ret = fetch(ctx, rs, i);
                            if(ret == 0) {
                                fetch_break = 1;
                                break;
                            } else if(ret < 0) {
                                fetch_break = 1;
                                res = FALSE;
                                break;
                            }
                        }
                    }
                    //fetch可能出错
                    if(fetch_break == 0) {
                        oci_err = oci_get_last_error();
                        code = oci_get_error_code(oci_err);
                        if(code != 0 && code != 1403) {
                            res = FALSE;
                        } else {
                            oci_err = NULL;
                        }
                    }
                }
            }
        }

        if(res == TRUE) {
            count = oci_get_row_count(stmt);
        }
        oci_statement_free(stmt);
    }

    if(oci_err != NULL && err_msg != NULL) {
        cstr_copy(err_msg, oci_get_error_msg(oci_err), err_size);
    }

    return count;
}

/**
*测试功能表达式
*@param test 表达式
*@return 结果真返回1,结果假返回0
*/
int fun_config_test_value(char *test, process_ctx_t *ctx, json_object *request) {
    int test_value = 1;
    if(!cstr_empty(test)) {
        exp_context_t exp_ctx;
        void *data[] = {ctx, request};
        exp_ctx.data = data;
        exp_ctx.get = get_value;
        test_value = test_exp(&exp_ctx, test);
    }

    //dcs_log(0, 0, "at %s(%s:%d) %d %s",__FUNCTION__,__FILE__,__LINE__,test_value, json_object_to_json_string(request));

    return test_value;
}

int module_select_one(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[2];
    int params_len;
    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf;
    carray_t bind;
    char *key;
    json_object *data;

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len <= 0) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误",__FUNCTION__,__FILE__,__LINE__,config->module_name);
        return -1;
    }

    //organize json
    key = "data";
    if(params_len > 1) {
        key = params[1];
    }

    if(strcmp(key, "request") == 0) {
        data = request;
    } else {
        data = json_util_object_get(response, key);
        if(data == NULL) {
            data = json_object_new_object();
            json_object_object_add(response, key, data);
        }
    }

    cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    carray_init(&bind, NULL);

    if(generate_sql(&sql_ctx, params[0], &sqlbuf, &bind) != 0) {
        ret = -1;
        snprintf(err_msg, err_size, "系统错误,生成SQL失败");
    } else {
        if(sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, select_fetch_row_handler, data, err_msg, err_size) < 0) {
            dcs_log(0, 0, "at %s(%s:%d) db_execute_select fail",__FUNCTION__,__FILE__,__LINE__);
            ret = -1;
        }
    }
    carray_destory(&bind);
    cbuf_destroy(&sqlbuf);

    return ret;
}

int module_batch_select_one(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    int i, len;


    if(json_object_get_type(request) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "数据不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
    } else {
        len = json_object_array_length(request);

        for(i = 0; i < len; i ++) {
            json_object *row = json_object_array_get_idx(request, i);

            if(module_select_one(config, ctx, row, response, err_msg, err_size) < 0) {
                ret = -1;
                break;
            }
        }
    }

    return ret;
}


int module_select_page(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[2];
    int params_len, page, page_size;
    char page_str[20], page_size_str[20];
    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf, totalbuf, rowsbuf;
    carray_t bind;
    char *key, *sql_stmt, *start, *end;
    const char *p;
    json_object *rows;

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len <= 0) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误",__FUNCTION__,__FILE__,__LINE__,config->module_name);
        return -1;
    }

    //organize json
    key = "rows";
    if(params_len > 1) {
        key = params[1];
    }

    rows = json_util_object_get(response, key);
    if(rows == NULL) {
        rows = json_object_new_array();
        json_object_object_add(response, key, rows);
    }

    cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    cbuf_init(&totalbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    cbuf_init(&rowsbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    carray_init(&bind, NULL);


    if(generate_sql(&sql_ctx, params[0], &sqlbuf, &bind) != 0) {
        ret = -1;
        snprintf(err_msg, err_size, "系统错误,生成SQL失败");
    } else {
        p = json_util_object_get_string(request, "page");
        if(p == NULL) {
            p = "1";
        }
        page = atoi(p);

        p = json_util_object_get_string(request, "rows");
        if(p == NULL) {
            p = "10";
        }
        page_size = atoi(p);

        if(page <= 0) {
            page = 1;
        }

        if(page_size <= 0) {
            page_size = 10;
        }

        sql_stmt = cbuf_str(&sqlbuf);
        start = strstr(sql_stmt, " from ");
        end = strstr(sql_stmt, " order by ");

        if(start == NULL) {
            goto error;
        }

        if(end == NULL) {
            end = sql_stmt + strlen(sql_stmt);
        }

        cbuf_append(&totalbuf, SELECT_TOTAL, sizeof(SELECT_TOTAL)-1);
        cbuf_append(&totalbuf, start,  end - start);


        if(sql_execute(ctx->con, cbuf_str(&totalbuf), &bind, select_fetch_total_handler, response, err_msg, err_size) < 0) {
            dcs_log(0, 0, "at %s(%s:%d) db_execute_select fail",__FUNCTION__,__FILE__,__LINE__);
            ret = -1;
            goto error;
        }

        int l = carray_size(&bind);

        cbuf_append(&rowsbuf, SELECT_PAGE_START, sizeof(SELECT_PAGE_START)-1);
        cbuf_append(&rowsbuf, sql_stmt,  strlen(sql_stmt));
        cbuf_printf(&rowsbuf, SELECT_PAGE_END, l, l + 1, l + 2, l + 3);

        snprintf(page_str, sizeof(page_str), "%d", page);
        snprintf(page_size_str, sizeof(page_size_str), "%d", page_size);

        carray_append(&bind, page_str);
        carray_append(&bind, page_size_str);
        carray_append(&bind, page_str);
        carray_append(&bind, page_size_str);

        void *fetch_ctx[] = {&page_size, rows};
        if(sql_execute(ctx->con, cbuf_str(&rowsbuf), &bind, select_fetch_rows_handler, fetch_ctx, err_msg, err_size) < 0) {
            dcs_log(0, 0, "at %s(%s:%d) db_execute_select fail",__FUNCTION__,__FILE__,__LINE__);
            ret = -1;
        }
    }
error:

    carray_destory(&bind);
    cbuf_destroy(&rowsbuf);
    cbuf_destroy(&totalbuf);
    cbuf_destroy(&sqlbuf);

    return ret;
}

int module_select_list(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[3], *key, *temp_key;
    int params_len, rowcount;
    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf;
    carray_t bind;
    json_object *rows;

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len <= 0) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误",__FUNCTION__,__FILE__,__LINE__,config->module_name);
        return -1;
    }

    //organize json
    key = "rows";
    if(params_len > 1) {
        key = params[1];
    }

    rowcount = 1000;
    if(params_len > 2) {
        rowcount = atoi(params[2]);
    }

    if(strcmp(key, "request") == 0) {
        rows = json_object_new_array();
        json_object_object_add(request, "rows", rows);
    } else if(strncmp(key, "request.", 8) == 0) {
        temp_key = key + 8;
        rows = json_object_new_array();
        json_object_object_add(request, temp_key, rows);
    } else {
        rows = json_object_new_array();
        json_object_object_add(response, key, rows);
    }

    cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    carray_init(&bind, NULL);

    if(generate_sql(&sql_ctx, params[0], &sqlbuf, &bind) != 0) {
        ret = -1;
        snprintf(err_msg, err_size, "系统错误,生成SQL失败");
    } else {
        //dcs_debug(0, 0, "[%s] %d", cbuf_str(&sqlbuf), carray_size(&bind));
        void *fetch_ctx[] = {&rowcount, rows};
        if(sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, select_fetch_rows_handler, fetch_ctx, err_msg, err_size) < 0) {
            ret = -1;
        }
    }
    carray_destory(&bind);
    cbuf_destroy(&sqlbuf);

    return ret;
}

int module_batch_select_list(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    int i, len;


    if(json_object_get_type(request) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "数据不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
    } else {
        len = json_object_array_length(request);

        for(i = 0; i < len; i ++) {
            json_object *row = json_object_array_get_idx(request, i);

            if(module_select_list(config, ctx, row, response, err_msg, err_size) < 0) {
                ret = -1;
                break;
            }
        }
    }

    return ret;
}


int module_select_column_list(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[3], *key, *temp_key;
    int params_len, rowcount;
    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf;
    carray_t bind;
    json_object *rows;

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len <= 0) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误",__FUNCTION__,__FILE__,__LINE__,config->module_name);
        return -1;
    }

    //organize json
    key = "rows";
    if(params_len > 1) {
        key = params[1];
    }

    rowcount = 1000;
    if(params_len > 2) {
        rowcount = atoi(params[2]);
    }

    if(strcmp(key, "request") == 0) {
        rows = json_object_new_array();
        json_object_object_add(request, "rows", rows);
    } else if(strncmp(key, "request.", 8) == 0) {
        temp_key = key + 8;
        rows = json_object_new_array();
        json_object_object_add(request, temp_key, rows);
    } else {
        rows = json_object_new_array();
        json_object_object_add(response, key, rows);
    }

    cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    carray_init(&bind, NULL);

    if(generate_sql(&sql_ctx, params[0], &sqlbuf, &bind) != 0) {
        ret = -1;
        snprintf(err_msg, err_size, "系统错误,生成SQL失败");
    } else {
        //dcs_debug(0, 0, "[%s] %d", cbuf_str(&sqlbuf), carray_size(&bind));
        void *fetch_ctx[] = {&rowcount, rows};
        if(sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, select_fetch_column_handler, fetch_ctx, err_msg, err_size) < 0) {
            ret = -1;
        }
    }
    carray_destory(&bind);
    cbuf_destroy(&sqlbuf);

    return ret;
}


int module_batch_select_column_list(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    int i, len;


    if(json_object_get_type(request) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "数据不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
    } else {
        len = json_object_array_length(request);

        for(i = 0; i < len; i ++) {
            json_object *row = json_object_array_get_idx(request, i);

            if(module_select_column_list(config, ctx, row, response, err_msg, err_size) < 0) {
                ret = -1;
                break;
            }
        }
    }

    return ret;
}


int check_data_acl(process_ctx_t *ctx, sql_ctx_t *sql_ctx, char *stmt_id, json_object *request, int rowcount) {
    int ret = 0, count = -1;
    cbuf_t sqlbuf, acl_sqlbuf;;
    carray_t bind;
    cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    cbuf_init(&acl_sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    carray_init(&bind, NULL);
    if(generate_sql(sql_ctx, stmt_id, &sqlbuf, &bind) != 0) {
        ret = -1;
        //snprintf(err_msg, err_size, "系统错误,生成SQL失败");
    } else {
        char *start;
        start = strstr(cbuf_str(&sqlbuf), " from ");
        if(start == NULL) {
            //配置错误
            ret = -1;
            dcs_log(0, 0, "at %s(%s:%d) 配置错误\n%s",__FUNCTION__,__FILE__,__LINE__,cbuf_str(&sqlbuf));
        } else {
            cbuf_append(&acl_sqlbuf, SELECT_TOTAL, sizeof(SELECT_TOTAL)-1);
            cbuf_append(&acl_sqlbuf, start, strlen(start));

            if(sql_execute(ctx->con, cbuf_str(&acl_sqlbuf), &bind, select_fetch_count_handler, &count, NULL, 0) <= 0) {
                ret = -1;
            } else if(rowcount != count) {
                //数据权限检查失败
                ret = -1;
                dcs_log(0, 0, "at %s(%s:%d) 数据权限检查失败 [%d][%d]",__FUNCTION__,__FILE__,__LINE__,rowcount,count);
            }
        }
    }
    cbuf_destroy(&sqlbuf);
    cbuf_destroy(&acl_sqlbuf);
    carray_destory(&bind);

    return ret;
}

int module_insert(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0, rowcount = 0;
    char param_list[512+1];
    char *params[3], *sql_id = NULL, *data_sql_id = NULL, *key_sql_id = NULL; //最多3个参数
    int params_len;

    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf;
    carray_t bind;

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));
    if(params_len < 1) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误",__FUNCTION__,__FILE__,__LINE__,config->module_name);
        return -1;
    }

    sql_id = params[0];

    if(params_len > 1) {
        data_sql_id = params[1];
    }

    if(params_len > 2) {
        key_sql_id = params[2];
    }

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    dcs_debug(0, 0, "at %s(%s:%d) [%s][%d]",__FUNCTION__,__FILE__,__LINE__,config->param_list,params_len);

    //生成key
    if(!cstr_empty(key_sql_id)) {

        cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
        carray_init(&bind, NULL);

        if(generate_sql(&sql_ctx, key_sql_id, &sqlbuf, &bind) != 0) {
            ret = -1;
            snprintf(err_msg, err_size, "系统错误,生成SQL失败");
        } else {
            if(sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, select_fetch_row_handler, request, err_msg, err_size) < 0) {
                dcs_log(0, 0, "at %s(%s:%d) sql_execute fail",__FUNCTION__,__FILE__,__LINE__);
                ret = -1;
            }
        }

        carray_destory(&bind);
        cbuf_destroy(&sqlbuf);
    }

    if(ret == 0) {
        //执行insert
        cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
        carray_init(&bind, NULL);

        if(generate_sql(&sql_ctx, sql_id, &sqlbuf, &bind) != 0) {
            ret = -1;
            snprintf(err_msg, err_size, "系统错误,生成SQL失败");
        } else {
            //dcs_debug(0, 0, "[%s] %d", cbuf_str(&sqlbuf), carray_size(&bind));
            if((rowcount = sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, NULL, NULL, err_msg, err_size)) < 0) {
                ret = -1;
            } else if(!cstr_empty(data_sql_id) && check_data_acl(ctx, &sql_ctx, data_sql_id, request, rowcount) != 0) {
                //数据权限检查失败
                ret = -1;
                snprintf(err_msg, err_size, "没有权限操作当前记录,数据权限检查失败");
                dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
            }
        }

        carray_destory(&bind);
        cbuf_destroy(&sqlbuf);
    }

    return ret;
}

int module_batch_insert(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    int i, len;

    dcs_debug(0, 0, "at %s(%s:%d)",__FUNCTION__,__FILE__,__LINE__);

    if(json_object_get_type(request) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "数据不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
    } else {
        len = json_object_array_length(request);

        for(i = 0; i < len; i ++) {
            dcs_debug(0, 0, "at %s(%s:%d)",__FUNCTION__,__FILE__,__LINE__);
            json_object *row = json_object_array_get_idx(request, i);

            if(module_insert(config, ctx, row, response, err_msg, err_size) < 0) {
                ret = -1;
                break;
            }
            dcs_debug(0, 0, "at %s(%s:%d)",__FUNCTION__,__FILE__,__LINE__);
        }
    }

    dcs_debug(0, 0, "at %s(%s:%d)",__FUNCTION__,__FILE__,__LINE__);

    return ret;
}

int module_update(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0, rowcount = 0;
    char param_list[512+1];
    char *params[2]; //最多两个参数
    int params_len;

    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf;
    carray_t bind;

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    carray_init(&bind, NULL);

    if(generate_sql(&sql_ctx, params[0], &sqlbuf, &bind) != 0) {
        ret = -1;
        snprintf(err_msg, err_size, "系统错误,生成SQL失败");
    } else {
        //dcs_debug(0, 0, "[%s] %d", cbuf_str(&sqlbuf), carray_size(&bind));

        if((rowcount = sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, NULL, NULL, err_msg, err_size)) < 0) {
            ret = -1;
        } else if(rowcount == 0) {
            //未找到可更新的数据
            ret = -1;
            snprintf(err_msg, err_size, "未找到可更新的数据,请确认有权限操作当前记录");
            dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
        } else if(params_len > 1 && check_data_acl(ctx, &sql_ctx, params[1], request, rowcount) != 0) {
            //数据权限检查失败
            ret = -1;
            snprintf(err_msg, err_size, "没有权限操作当前记录,数据权限检查失败");
            dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
        }
    }

    carray_destory(&bind);
    cbuf_destroy(&sqlbuf);

    return ret;
}


int module_batch_update(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    int i, len;

    if(json_object_get_type(request) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "数据不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
    } else {
        len = json_object_array_length(request);

        for(i = 0; i < len; i ++) {
            //dcs_debug(0, 0, "at %s(%s:%d)",__FUNCTION__,__FILE__,__LINE__);
            json_object *row = json_object_array_get_idx(request, i);

            if(module_update(config, ctx, row, response, err_msg, err_size) < 0) {
                ret = -1;
                break;
            }
            //dcs_debug(0, 0, "at %s(%s:%d)",__FUNCTION__,__FILE__,__LINE__);
        }
    }

    return ret;
}



int module_delete(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0, rowcount = 0;
    char param_list[512+1];
    char *params[2]; //最多两个参数
    int params_len;

    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf;
    carray_t bind;

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    carray_init(&bind, NULL);

    if(generate_sql(&sql_ctx, params[0], &sqlbuf, &bind) != 0) {
        ret = -1;
        snprintf(err_msg, err_size, "系统错误,生成SQL失败");
    } else {
        //dcs_debug(0, 0, "[%s] %d", cbuf_str(&sqlbuf), carray_size(&bind));

        if((rowcount = sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, NULL, NULL, err_msg, err_size)) < 0) {
            ret = -1;
        } else if(params_len > 1 && atoi(params[1]) > rowcount) {
            //未找到可删除的数据
            ret = -1;
            snprintf(err_msg, err_size, "未找到可删除的数据");
            dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
        }
    }

    carray_destory(&bind);
    cbuf_destroy(&sqlbuf);

    return ret;
}

int module_batch_delete(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    int i, len;

    if(json_object_get_type(request) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__, err_size, err_msg);
    } else {
        len = json_object_array_length(request);

        for(i = 0; i < len; i ++) {
            json_object *row = json_object_array_get_idx(request, i);

            if(module_delete(config, ctx, row, response, err_msg, err_size) < 0) {
                ret = -1;
                break;
            }
        }
    }

    return ret;
}


int module_callproc(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[128];
    int params_len;
    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf;
    carray_t bind;
    char out_param[MAX_OUT_SIZE][MAX_OUT_VARCHAR_SIZE];
    int out_count = 0;
    void *sql_data[] = {ctx, request};

    //dcs_debug(0, 0, "xjb %s %s", config->test, json_object_to_json_string(request));

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
    carray_init(&bind, NULL);

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len <= 0) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误",__FUNCTION__,__FILE__,__LINE__,config->module_name);
        return -1;
    }

    //第一个参数是存储过程名
    cbuf_printf(&sqlbuf, "begin %s(", params[0]);

    int i;
    for(i = 1; i < params_len; i ++) {
        if(i == 1) {
            cbuf_printf(&sqlbuf, ":b%d", i-1);
        } else {
            cbuf_printf(&sqlbuf, ",:b%d", i-1);
        }

        if(params[i][0] == '#') {
            //目前只支持一个输出
            memset(out_param[out_count], ' ', sizeof(out_param[out_count]));
            out_param[out_count][sizeof(out_param[out_count])-1] = '\0';
            carray_append(&bind, out_param[out_count]);
            out_count ++;
        } else if(params[i][0] == ':') {
            carray_append(&bind, get_value(sql_data, params[i]+1));
        } else {
            carray_append(&bind, params[i]);
        }
    }

    cbuf_printf(&sqlbuf, "); end;");

    //dcs_debug(0, 0, "[%s] %d", cbuf_str(&sqlbuf), carray_size(&bind));
    print_bind(&bind);
    if(sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, NULL, NULL, err_msg, err_size) < 0) {
        ret = -1;
    } else {
        out_count = 0;
        for(i = 1; i < params_len; i ++) {
            if(params[i][0] == '#') {
                //目前只支持一个输出
                cstr_rtrim(out_param[out_count]);
                dcs_debug(0, 0, "out[%s]", out_param[out_count]);
                json_object_object_add(request, params[i]+1, json_object_new_string(out_param[out_count]));
                out_count ++;
            }
        }
    }

    carray_destory(&bind);
    cbuf_destroy(&sqlbuf);

    return ret;
}

int module_batch_callproc(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    int i, len;

    if(json_object_get_type(request) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__, err_size, err_msg);
    } else {
        len = json_object_array_length(request);

        for(i = 0; ret == 0 && i < len; i ++) {
            json_object *row = json_object_array_get_idx(request, i);
            json_object *temp = row;

            //非object处理
            if(json_object_get_type(row) != json_type_object) {
                temp = json_object_new_object();
                json_object_object_add(temp, config->input, row);
                json_object_get(row); //计数加1
            }

            if(module_callproc(config, ctx, temp, response, err_msg, err_size) < 0) {
                ret = -1; //break
            }

            if(json_object_get_type(row) != json_type_object) {
                json_object_put(temp);
            }
        }
    }

    return ret;
}

static json_object *json_util_copy_get(char *dest, json_object *request, json_object *response) {
    json_object *dest_json = NULL;

    char dest_copy[128+1];
    char *params[2];
    int params_len;

    cstr_copy(dest_copy, dest, sizeof(dest_copy));
    params_len = cstr_split(dest_copy, ".", params, ARRAY_SIZE(params));

    if(strcmp(params[0], "request") == 0) {
        dest_json = request;
    } else if(strcmp(params[0], "response") == 0) {
        dest_json = response;
    }

    if(params_len > 1) {
        dest_json = json_util_object_get(dest_json, params[1]);
    }

    return dest_json;
}

static json_object *json_util_copy_add(char *dest, json_object *request, json_object *response, json_type type) {
    json_object *dest_json = NULL, *temp_json;

    char dest_copy[128+1];
    char *params[2];
    int params_len;

    cstr_copy(dest_copy, dest, sizeof(dest_copy));
    params_len = cstr_split(dest_copy, ".", params, ARRAY_SIZE(params));

    if(strcmp(params[0], "request") == 0) {
        dest_json = request;
    } else if(strcmp(params[0], "response") == 0) {
        dest_json = response;
    }

    if(params_len > 1) {
        temp_json = json_util_object_get(dest_json, params[1]);
        if(temp_json == NULL) {
            if(type == json_type_object) {
                temp_json = json_object_new_object();
            } else if(type == json_type_array) {
                temp_json = json_object_new_array();
            }

            json_object_object_add(dest_json, params[1], temp_json);
        }

        dest_json = temp_json;
    }

    return dest_json;
}


int module_copy(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[4];
    int params_len;
    char *from, *to, *key, *new_key;
    json_object *from_json, *to_json, *key_obj;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 4) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误:%s",__FUNCTION__,__FILE__,__LINE__,config->module_name,config->param_list);
        return -1;
    }

    from = params[0];
    to = params[1];
    key = params[2];
    new_key = params[3];

    from_json = json_util_copy_get(from, request, response);
    to_json = json_util_copy_get(to, request, response);

    if(to_json == NULL) {
        to_json = json_util_copy_add(to, request, response, json_type_object);
    }

    if(from_json == NULL || to_json == NULL) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误:%s",__FUNCTION__,__FILE__,__LINE__,config->module_name,config->param_list);
        return -1;
    }

    //dest_obj = json_object_new_object();
    //json_object_object_add(to_json, dest, dest_obj);

    key_obj = json_util_object_get(from_json, key);

    //dcs_debug(0, 0, "at %s(%s:%d)\n%s",__FUNCTION__,__FILE__,__LINE__,json_object_to_json_string(from_json));
    if(json_object_get_type(to_json) != json_type_object) {
        ret = -1;
        snprintf(err_msg, err_size, "%s不是对象,不能进行操作", to);
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__, err_size, err_msg);
    } else {
        json_object_object_add(to_json, new_key, json_object_get(key_obj));
    }

    return ret;
}


int module_batch_copy(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0, len, i;
    char param_list[512+1];
    char *params[4];
    int params_len;
    char *from, *to, *key, *new_key;
    json_object *from_json, *to_json, *key_obj;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 4) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误:%s",__FUNCTION__,__FILE__,__LINE__,config->module_name,config->param_list);
        return -1;
    }

    from = params[0];
    to = params[1];
    key = params[2];
    new_key = params[3];

    from_json = json_util_copy_get(from, request, response);
    to_json = json_util_copy_get(to, request, response);

    if(from_json == NULL || to_json == NULL) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误:%s ",__FUNCTION__,__FILE__,__LINE__,config->module_name,config->param_list);
        return -1;
    }

    key_obj = json_util_object_get(from_json, key);

    if(json_object_get_type(to_json) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "%s不是数组,不能进行批量操作", to);
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__, err_size, err_msg);
    } else {
        len = json_object_array_length(to_json);
        for(i = 0; i < len; i ++) {
            json_object *temp = json_object_array_get_idx(to_json, i);
            if(json_object_get_type(temp) != json_type_object) {
                ret = -1;
                dcs_log(0, 0, "at %s(%s:%d) %s不是对象数组",__FUNCTION__,__FILE__,__LINE__, to);
                break;
            } else {
                json_object_object_add(temp, new_key, key_obj);
                json_object_get(key_obj);
            }
        }
    }

    return ret;
}


int module_add(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0, i;
    char param_list[512+1];
    char *params[8];
    int params_len;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len%2 != 0) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误:%s",__FUNCTION__,__FILE__,__LINE__,config->module_name,config->param_list);
        return -1;
    }

    for(i = 0; i < params_len; i +=2) {
        json_object_object_add(request, params[i], json_object_new_string(params[i+1]));
    }

    return ret;
}


int module_del(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0, i;
    char param_list[512+1];
    char *params[10];
    int params_len;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    for(i = 0; i < params_len; i +=1) {
        json_object_put(json_util_object_get(request, params[i]));
    }

    return ret;
}



int create_file(char *url, size_t url_size, char *prefix, char *suffix) {
    int fd = -1;

    char datetime[20];
    struct tm now = cdate_now();
    cdate_strftime(&now, "%Y%m%d%H%M%S", datetime, sizeof(datetime));

    //unsigned char uuid_buf[33];
    //gen_uuid(uuid_buf);

    char microseconds[20];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    snprintf(microseconds, sizeof(microseconds), "%ld", tv.tv_usec);

    char filepath[CFILE_MAX_PATH];
    char filedir[CFILE_MAX_PATH];

    //char *prefix = "mchnt_";
    snprintf(url, url_size, "/download/%.8s/%s%.8s_%s_%s.%s", datetime, prefix, datetime, datetime+8, microseconds, suffix);
    snprintf(filedir, sizeof(filedir), "%s/download/%.8s", document_root, datetime);
    snprintf(filepath, sizeof(filepath), "%s%s", document_root, url);


    if(cfile_mkdirs(filedir, CFILE_DEFAULT_DIR_MODE) != 0) {
        dcs_log(0,0,"at %s(%s:%d) 创建目录[%s]出错",__FUNCTION__,__FILE__,__LINE__,filedir);
    } else if((fd = open(filepath, O_CREAT|O_EXCL|O_RDWR, S_IRWXU | S_IRWXG | S_IROTH)) < 0) {
        dcs_log(0,0,"at %s(%s:%d) 文件已经存在[%s]",__FUNCTION__,__FILE__,__LINE__,filepath);
    }

    return fd;
}


int module_export_txt(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[3], *sql_id, *delim, *prefix;
    int params_len;
    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf;
    carray_t bind;

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 3) {
        dcs_log(0, 0, "at %s(%s:%d) %s模块参数配置错误",__FUNCTION__,__FILE__,__LINE__,config->module_name);
        return -1;
    }

    int fd = -1;
    char url[CFILE_MAX_PATH];

    sql_id = params[0];
    delim = params[1];
    prefix = params[2];
    if(cstr_empty(delim)) {
        delim = ",";
    }

    bzero(url, sizeof(url));
    if((fd = create_file(url, sizeof(url), prefix, "txt")) < 0) {
        ret = -1;
        snprintf(err_msg, err_size, "创建文件失败");
        dcs_log(0, 0, "at %s(%s:%d) %s[%s]",__FUNCTION__,__FILE__,__LINE__,err_msg,url);
    } else {
        dcs_log(0, 0, "at %s(%s:%d) fd[%d]",__FUNCTION__,__FILE__,__LINE__,fd);
        cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
        carray_init(&bind, NULL);

        if(generate_sql(&sql_ctx, sql_id, &sqlbuf, &bind) != 0) {
            ret = -1;
            snprintf(err_msg, err_size, "系统错误,生成SQL失败");
        } else {
            void *fetch_ctx[] = {&fd, delim};

            if(sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, select_fetch_export_txt_handler, fetch_ctx, err_msg, err_size) < 0) {
                ret = -1;
            } else {
                json_object_object_add(response, "url", json_object_new_string(url));
            }
        }
        carray_destory(&bind);
        cbuf_destroy(&sqlbuf);

        close(fd);
    }

    return ret;
}


int module_export_xls(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0, i;
    char param_list[512+1];
    char *params[20], *template_file, *prefix, *suffix;
    int params_len, row, col;
    sql_ctx_t sql_ctx;
    cbuf_t sqlbuf;
    carray_t bind;

    //init sql_ctx
    sql_ctx_init(&sql_ctx, request, ctx, get_current_value, gen_data_acl);

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 6 || (params_len-2)%4 != 0) {
        snprintf(err_msg, err_size, "%s模块参数配置错误", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    int fd = -1;
    char url[CFILE_MAX_PATH];
    char filename[CFILE_MAX_PATH];
    char *p;

    template_file = params[0];
    prefix = params[1];

    //计算后缀
    suffix = "xls";
    p = template_file + strlen(template_file);
    while(--p >= template_file) {
        if(*p == '.') {
            suffix = p + 1;
            break;
        }
    }

    bzero(url, sizeof(url));
    if((fd = create_file(url, sizeof(url), prefix, suffix)) < 0) {
        ret = -1;
        snprintf(err_msg, err_size, "创建文件失败");
        dcs_log(0, 0, "at %s(%s:%d) %s[%s]",__FUNCTION__,__FILE__,__LINE__,err_msg,url);
    } else {
        dcs_log(0, 0, "at %s(%s:%d) fd[%d]",__FUNCTION__,__FILE__,__LINE__, fd);
        close(fd); //关闭文件

        BookHandle book = NULL;
        SheetHandle sheet = NULL;

        snprintf(filename, sizeof(filename), "%s/template/%s", document_root, template_file);
        //拷贝模板文件,加载模板
        if(strcmp(suffix, "xlsx") == 0) {
            book = xlCreateXMLBook();
        } else {
            book = xlCreateBook();
        }

        if(book == NULL || xlBookLoad(book,filename) == 0) {
            ret = -1;
            snprintf(err_msg, err_size, "加载模板文件%s失败", template_file);
        } else {

            cbuf_init(&sqlbuf, DEFAULT_SQL_SIZE, MAX_SQL_SIZE);
            for(i = 2; ret == 0 && i < params_len; i += 4) {
                if((sheet = xlBookGetSheet(book, atoi(params[i+1]))) == NULL) {

                    ret = -1;
                    snprintf(err_msg, err_size, "sheet下标配置错误");
                    dcs_log(0, 0, "at %s(%s:%d) %s[%s]",__FUNCTION__,__FILE__,__LINE__,err_msg, params[i+1]);
                } else {
                    row = atoi(params[i+2]);
                    col = atoi(params[i+3]);

                    void *fetch_ctx[] = {sheet, &row, &col};

                    cbuf_reset(&sqlbuf);
                    carray_init(&bind, NULL);
                    if(generate_sql(&sql_ctx, params[i], &sqlbuf, &bind) != 0) {
                        ret = -1;
                        snprintf(err_msg, err_size, "SQL配置错误");
                        dcs_log(0, 0, "at %s(%s:%d) %s[%s]",__FUNCTION__,__FILE__,__LINE__,err_msg, params[i]);
                    } else if(sql_execute(ctx->con, cbuf_str(&sqlbuf), &bind, select_fetch_export_xls_handler, fetch_ctx, err_msg, err_size) < 0) {
                        ret = -1;
                    }
                    carray_destory(&bind);
                }
            }


            if(ret == 0) {
                snprintf(filename, sizeof(filename), "%s%s", document_root, url);
                if(xlBookSave(book, filename) == 0) {
                    ret = -1;
                    snprintf(err_msg, err_size, "保存文件失败");
                } else {
                    json_object_object_add(response, "url", json_object_new_string(url));
                }
            }

            cbuf_destroy(&sqlbuf);
        }

        if(book != NULL) {
            xlBookRelease(book);
        }
    }

    return ret;
}


int module_check_sign(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[8];
    int params_len;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    const char *sign_sek_indx = json_util_object_get_string(request, params[0]);
    const char *sign_key = json_util_object_get_string(request, params[1]);

    if(cstr_empty(ctx->sign) || cstr_empty(ctx->body) || cstr_empty(sign_sek_indx) || cstr_empty(sign_key)) {
        snprintf(err_msg, err_size, "签名验证失败");
        ret = -1;
        dcs_log(0, 0, "at %s(%s:%d) 签名要素不全",__FUNCTION__,__FILE__,__LINE__);
    } else {
        char buf[33], buf_hex[33];
        int buf_len = 0;
        char sign_key_data[24];

        bzero(buf, sizeof(buf));
        bzero(buf_hex, sizeof(buf_hex));
        //md5(buf, ctx->body, sign_key, 0);

        char return_code[4];

        bzero(return_code, sizeof(return_code));

        bzero(sign_key_data, sizeof(sign_key_data));
        cbin_hex_to_bin((const unsigned char *)sign_key, (unsigned char *)sign_key_data, strlen(sign_key));

        dcs_log(0, 0, "at %s(%s:%d) [%d]",__FUNCTION__,__FILE__,__LINE__,ctx->body_len);

        DES_TO_MD5(return_code, (char *)sign_sek_indx,(char *)sign_key_data, ctx->body_len, (char *)ctx->body, &buf_len, buf);

        cbin_bin_to_hex((unsigned char *)buf, (unsigned char *)buf_hex, buf_len);

        /*
        cmd5_ctx_t md5;
        cmd5_init(&md5);
        cmd5_update(&md5, (unsigned char *)ctx->body, ctx->body_len);
        cmd5_update(&md5, (unsigned char *)sign_key, strlen(sign_key));
        cmd5_hexdigest(&md5, (unsigned char *)buf);
        */

        if(strcasecmp(ctx->sign, buf_hex) != 0) {
            snprintf(err_msg, err_size, "签名验证失败");
            ret = -1;
            dcs_log(0, 0, "at %s(%s:%d) [%s] [%s]",__FUNCTION__,__FILE__,__LINE__,ctx->sign, buf_hex);
        }
    }

    return ret;
}

int module_generate_tmk(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[8];
    int params_len;

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 5) {
        snprintf(err_msg, err_size, "%s模块参数配置错误", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    const char *sek_indx = json_util_object_get_string(request, params[0]);
    const char *tek_indx = json_util_object_get_string(request, params[1]);
    const char *tmk_key1 = params[2];
    const char *tmk_key2 = params[3];
    const char *sql_id = params[4];

    char return_code[4];
    char sek_tmk_data[100];
    char tek_tmk_data[100];
    char chk_tmk_data[100];

    char sek_tmk_hex[100];
    char tek_tmk_hex[100];
    char chk_tmk_hex[100];

    bzero(return_code, sizeof(return_code));
    bzero(sek_tmk_data, sizeof(sek_tmk_data));
    bzero(tek_tmk_data, sizeof(tek_tmk_data));
    bzero(chk_tmk_data, sizeof(chk_tmk_data));
    bzero(sek_tmk_hex, sizeof(sek_tmk_hex));
    bzero(tek_tmk_hex, sizeof(tek_tmk_hex));
    bzero(chk_tmk_hex, sizeof(chk_tmk_hex));

    GET_TMK(return_code, (char *)sek_indx, (char *)tek_indx, 2, sek_tmk_data, tek_tmk_data, chk_tmk_data);

    cbin_bin_to_hex((unsigned char *)sek_tmk_data, (unsigned char *)sek_tmk_hex, 16);
    cbin_bin_to_hex((unsigned char *)tek_tmk_data, (unsigned char *)tek_tmk_hex, 16);
    cstr_upper(sek_tmk_hex);
    cstr_upper(tek_tmk_hex);

    fun_config_t temp_config;
    //memcpy(&temp_config, config, sizeof(temp_config));
    bzero(&temp_config, sizeof(temp_config));
    cstr_copy(temp_config.param_list, sql_id, sizeof(temp_config.param_list));

    json_object_object_add(request, tmk_key1, json_object_new_string(sek_tmk_hex));
    json_object_object_add(request, tmk_key2, json_object_new_string(tek_tmk_hex));

    if(module_update(&temp_config, ctx, request, response, err_msg, err_size) < 0) {
        ret = -1;
    }

    return ret;
}

int module_generate_sign_key(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[8];
    int params_len;

    //前提表达式检测
    if(!fun_config_test_value(config->test, ctx, request)) {
        return 0;
    }

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 5) {
        snprintf(err_msg, err_size, "%s模块参数配置错误", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    const char *sek_indx = json_util_object_get_string(request, params[0]);
    const char *sign_sek_indx = json_util_object_get_string(request, params[1]);
    const char *tmk_key1 = json_util_object_get_string(request, params[2]);
    const char *sign_key = params[3];
    const char *sql_id = params[4];

    char return_code[4];
    char sek_pikmak_data[100];
    char tmk_pikmak_data[100];
    char chk_pikmak_data[100];
    char sek_pikmak_hex[100];
    char tmk_pikmak_hex[100];
    char chk_pikmak_hex[100];

    bzero(return_code, sizeof(return_code));
    bzero(sek_pikmak_data, sizeof(sek_pikmak_data));
    bzero(tmk_pikmak_data, sizeof(tmk_pikmak_data));
    bzero(chk_pikmak_data, sizeof(chk_pikmak_data));
    bzero(sek_pikmak_hex, sizeof(sek_pikmak_hex));
    bzero(tmk_pikmak_hex, sizeof(tmk_pikmak_hex));
    bzero(chk_pikmak_hex, sizeof(chk_pikmak_hex));

    //GET_TMK(return_code, sek_indx, tek_indx, 2, sek_pikmak_data, tmk_pikmak_data, chk_pikmak_data);
    GET_WORK_KEY(return_code, (char *)sek_indx, (char *)sign_sek_indx, (char *)tmk_key1, 2, 2, sek_pikmak_data, tmk_pikmak_data, chk_pikmak_data);
    cbin_bin_to_hex((unsigned char *)sek_pikmak_data, (unsigned char *)sek_pikmak_hex, 16);
    cstr_upper(sek_pikmak_hex);

    //dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,sek_pikmak_hex);

    fun_config_t temp_config;
    //memcpy(&temp_config, config, sizeof(temp_config));
    bzero(&temp_config, sizeof(temp_config));
    cstr_copy(temp_config.param_list, sql_id, sizeof(temp_config.param_list));

    json_object_object_add(request, sign_key, json_object_new_string(sek_pikmak_hex));

    if(module_update(&temp_config, ctx, request, response, err_msg, err_size) < 0) {
        ret = -1;
    }

    return ret;
}


int module_rsa_pk_encrypt(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[8];
    int params_len;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 4) {
        snprintf(err_msg, err_size, "%s模块参数配置错误", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    const char *sek_indx = json_util_object_get_string(request, params[0]);
    const char *term_key1 = json_util_object_get_string(request, params[1]);
    const char *rsa_key = json_util_object_get_string(request, params[2]);
    const char *encrypt_key = params[3];

    dcs_log(0, 0, "%s", term_key1);
    dcs_log(0, 0, "%s", rsa_key);

    dcs_log(0, 0, "%s", json_object_to_json_string(request));

    if(cstr_empty(term_key1)) {
        snprintf(err_msg, err_size, "%s终端应用密钥为空", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    if(cstr_empty(rsa_key)) {
        snprintf(err_msg, err_size, "%s公钥为空", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    char rsa_key_bin[512];
    cbin_hex_to_bin((unsigned char *)rsa_key, (unsigned char *)rsa_key_bin, strlen(rsa_key));

    char return_code[4];
    char encrypt_data[512];
    int encrypt_data_len = 0;
    char encrypt_hex[2048+1];

    bzero(return_code, sizeof(return_code));
    bzero(encrypt_data, sizeof(encrypt_data));
    bzero(encrypt_hex, sizeof(encrypt_hex));

    dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,encrypt_hex);

    DES_TO_RSA_KEY(return_code, (char *)sek_indx, (char *)term_key1, strlen(rsa_key)/2, rsa_key_bin, &encrypt_data_len, encrypt_data);

    cbin_bin_to_hex((unsigned char *)encrypt_data, (unsigned char *)encrypt_hex, encrypt_data_len);
    cstr_upper(encrypt_hex);


    dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,encrypt_hex);

    json_object_object_add(request, encrypt_key, json_object_new_string(encrypt_hex));

    return ret;
}

int module_generate_para_file(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    char param_list[512+1];
    char *params[10];
    int params_len;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 6) {
        snprintf(err_msg, err_size, "%s模块参数配置错误", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    const char *file_path = json_util_object_get_string(request, params[0]);
    const char *mchnt_cd = json_util_object_get_string(request, params[1]);
    const char *term_id = json_util_object_get_string(request, params[2]);
    const char *psam_no = json_util_object_get_string(request, params[3]);
    const char *new_file_path = params[4];
    const char *file_name = json_util_object_get_string(request, params[5]);
    const char *para_sql_id = params[6];

    const char *manufacturer = json_util_object_get_string(request, "manufacturer");

    if(cstr_empty(manufacturer)) {
        snprintf(err_msg, err_size, "manufacturer为空");
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

	psam_no	 = (psam_no == NULL) ? "" : psam_no;
	mchnt_cd = (mchnt_cd == NULL) ? "" : mchnt_cd;
	term_id	 = (term_id == NULL) ? "" : term_id;

    //查询定制参数
    {
        fun_config_t temp_config;
        bzero(&temp_config, sizeof(temp_config));
        cstr_copy(temp_config.module_name, "select_list", sizeof(temp_config.module_name));
        snprintf(temp_config.param_list, sizeof(temp_config.param_list), "%s,request.para", para_sql_id);

		dcs_log(0, 0, "at %s(%s:%d)\n%s",__FUNCTION__,__FILE__,__LINE__,json_object_to_json_string(request));
		dcs_log(0, 0, "at %s(%s:%d)\n%s",__FUNCTION__,__FILE__,__LINE__,json_object_to_json_string(response));

        ret = execute_config(&temp_config, ctx, request, response, err_msg, err_size);
        if(ret != 0) {
            return ret;
        }
    }

    json_object *para = json_util_object_get(request, "para");

    char source_path[CFILE_MAX_PATH];
    char dest_path[CFILE_MAX_PATH];
    char file_url[CFILE_MAX_PATH];
    char today[20];
    unsigned char uuid_buf[33];
    char *suffix;

    cdate_now_date(today, sizeof(today));
    gen_uuid(uuid_buf);

    snprintf(source_path, sizeof(source_path), "%s%s", document_root, file_path);
    suffix = cfile_get_suffix(cfile_get_filename(source_path));
    suffix = (suffix == NULL ? "" : suffix);
    snprintf(dest_path, sizeof(dest_path), "%s/%s/%s/%s%s", document_root, "temp", today, uuid_buf, suffix);

    int fd;
    FILE *fw, *fp;
    if((fd = cfile_create(dest_path)) == -1) {
        snprintf(err_msg, err_size, "创建参数文件失败");
        dcs_log(0, 0, "at %s(%s:%d) %s[%s][%s]",__FUNCTION__,__FILE__,__LINE__,err_msg,source_path,dest_path);
        ret = -1;
    } else {
        close(fd);

        if((fw = fopen(dest_path, "wb")) == NULL) {
            snprintf(err_msg, err_size, "打开文件失败");
            dcs_log(0, 0, "at %s(%s:%d) %s[%s]",__FUNCTION__,__FILE__,__LINE__,err_msg,dest_path);
            ret = -1;
        } else if((fp = fopen(source_path, "rb")) == NULL) {
            snprintf(err_msg, err_size, "打开文件失败");
            dcs_log(0, 0, "at %s(%s:%d) %s[%s]",__FUNCTION__,__FILE__,__LINE__,err_msg,source_path);
            ret = -1;
        } else {
            char buf[MAX_BUFFER_SIZE*8];
            size_t n;

            n = fread(buf, 1, sizeof(buf)-1, fp);
            buf[n] = '\0';

            //新大陆
            if(strcmp(manufacturer, "NEWLAND") == 0) {
                newland_para_t newland;
                newland_para_init(&newland);
                parse_newland_para(buf, n, &newland);

                if(!cstr_empty(mchnt_cd) && !cstr_empty(term_id)) {
                    update_newland_para(&newland, "01000005", term_id);
                    update_newland_para(&newland, "01000001", mchnt_cd);
                }

                if(!cstr_empty(psam_no)) {
                    update_newland_para(&newland, "01000001", psam_no);;
                }

                newland_para_to_file(&newland, fw);

                newland_para_destroy(&newland);
            }

            //百富
            if(strcmp(manufacturer, "PAX") == 0) {
                pax_para_t pax;
                pax_para_init(&pax);
                parse_pax_para(buf, n, &pax);

                {
                    int i;
                    int len = json_object_array_length(para);
                    for(i = 0; i < len; i++) {
                        json_object *row = json_object_array_get_idx(para, i);
                        const char *para_name = json_util_object_get_string(row, "para_name");
                        const char *para_value = json_util_object_get_string(row, "para_value");

                        if(strcmp(para_value, "${PSAM}") == 0) {
                            update_pax_para(&pax, para_name, psam_no);
                        } else if(strcmp(para_value, "${MCHNT_CD}") == 0) {
                            update_pax_para(&pax, para_name, mchnt_cd);
                        } else if(strcmp(para_value, "${TERM_ID}") == 0) {
                            update_pax_para(&pax, para_name, term_id);
                        } else {
                            update_pax_para(&pax, para_name, para_value == NULL ? "" : para_value);
                        }
                    }
                }

                pax_para_to_file(&pax, fw);

                pax_para_destroy(&pax);
            }

            //新国都

            if(strcmp(manufacturer, "XGD") == 0) {
                if(buf[0] == '[') {

                    ini_parser_t *parser = ini_parser_new('#', '=');

                    ini_parse(parser, buf);

                    {
                        int i;
                        int len = json_object_array_length(para);
                        for(i = 0; i < len; i++) {
                            json_object *row = json_object_array_get_idx(para, i);
                            const char *para_name = json_util_object_get_string(row, "para_name");
                            const char *para_value = json_util_object_get_string(row, "para_value");

                            char tmpbuf[100];
                            bzero(tmpbuf, sizeof(tmpbuf));
                            cstr_copy(tmpbuf, para_name, sizeof(tmpbuf));
                            char *name[2];
                            int name_len = cstr_split(tmpbuf, ".", name, ARRAY_SIZE(name));
                            if(name_len != 2) {
                                //error
                                break;
                            }


							dcs_log(0, 0, "xjb[%s][%s]", name[0], name[1]);

                            if(strcmp(para_value, "${PSAM}") == 0) {
                                ini_set(parser, name[0], name[1], psam_no);
                            } else if(strcmp(para_value, "${MCHNT_CD}") == 0) {
                                ini_set(parser, name[0], name[1], mchnt_cd);
                            } else if(strcmp(para_value, "${TERM_ID}") == 0) {
                                ini_set(parser, name[0], name[1], term_id);
                            } else {
                                ini_set(parser, name[0], name[1], para_value == NULL ? "" : para_value);
                            }
                        }
                    }

                    ini_to_file(parser, fw);

                    ini_parser_free(parser);
                } else {

                    xgd_para_t xgd;
                    xgd_para_init(&xgd);
                    parse_xgd_para(buf, &xgd);

                    {
                        int i;
                        int len = json_object_array_length(para);
                        for(i = 0; i < len; i++) {
                            json_object *row = json_object_array_get_idx(para, i);
                            const char *para_name = json_util_object_get_string(row, "para_name");
                            const char *para_value = json_util_object_get_string(row, "para_value");

                            char tmpbuf[100];
                            bzero(tmpbuf, sizeof(tmpbuf));
                            cstr_copy(tmpbuf, para_name, sizeof(tmpbuf));
                            char *name[4];
                            int name_len = cstr_split(tmpbuf, ",", name, ARRAY_SIZE(name));
                            if(name_len != 4) {
                                //error
                                break;
                            }

                            if(strcmp(para_value, "${PSAM}") == 0) {
                                update_xgd_para(&xgd, name[0], atoi(name[1]), atoi(name[2]), atoi(name[3]), psam_no);;
                            } else if(strcmp(para_value, "${MCHNT_CD}") == 0) {
                                update_xgd_para(&xgd, name[0], atoi(name[1]), atoi(name[2]), atoi(name[3]), mchnt_cd);;
                            } else if(strcmp(para_value, "${TERM_ID}") == 0) {
                                update_xgd_para(&xgd, name[0], atoi(name[1]), atoi(name[2]), atoi(name[3]), term_id);;
                            } else {
                                update_xgd_para(&xgd, name[0], atoi(name[1]), atoi(name[2]), atoi(name[3]), para_value);
                            }
                        }
                    }

                    xgd_para_to_file(&xgd, fw);

                    xgd_para_destroy(&xgd);
                }
            }

            snprintf(file_url, sizeof(file_url), "%s?filename=%s", dest_path+strlen(document_root), file_name);

            json_object_object_add(request, new_file_path, json_object_new_string(file_url));
        }

        if(fw != NULL) {
            fclose(fw);
        }

        if(fp != NULL) {
            fclose(fp);
        }

        //json_object_object_add(request, new_file_path, json_object_new_string(source_path+strlen(document_root)));
    }

    return ret;
}

int module_batch_generate_para_file(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    int i, len;

    dcs_debug(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,json_object_to_json_string(request));

    if(json_object_get_type(request) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "数据不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
    } else {
        len = json_object_array_length(request);

        for(i = 0; i < len; i ++) {
            json_object *row = json_object_array_get_idx(request, i);

            if(module_generate_para_file(config, ctx, row, response, err_msg, err_size) < 0) {
                ret = -1;
                break;
            }
        }
    }

    return ret;
}

int module_extract_column_array(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0, i;
    char param_list[512+1];
    char *params[8];
    int params_len;
    int len;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 2) {
        snprintf(err_msg, err_size, "%s模块参数配置错误", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    const char *key = params[0];
    const char *column =  params[1];
    const char *new_key = params[2];
    json_object *array = json_util_object_get(request, key);
    json_object *new_array = NULL;


    if(json_object_get_type(array) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "数据不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
    } else {
        new_array = json_object_new_array();

        len = json_object_array_length(array);
        for(i = 0; i < len; i ++) {
            json_object *row = json_object_array_get_idx(array, i);
            json_object_array_add(new_array, json_object_get(json_util_object_get(row, column)));
            //json_object_array_add(new_array, json_object_new_string(""));
        }

        //key==new_key
        json_object_object_add(request, new_key, new_array);
        //json_object_put(new_array);
    }

    return ret;
}


int module_batch_execute(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;
    int i, len;
    char param_list[512+1];
    char *params[3]; //注意大小
    int params_len;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 3) {
        snprintf(err_msg, err_size, "%s模块参数配置错误", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }


    char *module_name = params[0];
    char *input_key = params[1];
    char *sub_params = params[2];

    dcs_debug(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,json_object_to_json_string(request));

    if(json_object_get_type(request) != json_type_array) {
        ret = -1;
        snprintf(err_msg, err_size, "数据不是数组,不能进行批量操作");
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__,err_size,err_msg);
    } else {
        len = json_object_array_length(request);

        for(i = 0; i < len; i ++) {
            json_object *row = json_object_array_get_idx(request, i);

            fun_config_t temp_config;
            memcpy(&temp_config, config, sizeof(temp_config));
            cstr_copy(temp_config.module_name, module_name, sizeof(temp_config.module_name));
            cstr_copy(temp_config.input, input_key, sizeof(temp_config.input));
            cstr_copy(temp_config.param_list, sub_params, sizeof(temp_config.param_list));

            ret = execute_config(&temp_config, ctx, row, response, err_msg, err_size);
        }
    }

    return ret;
}


int module_create_session(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    int ret = 0;

    char param_list[512+1];
    char *params[10]; //注意大小
    int params_len;
    int seconds;
    const char *sn;
    const char *manufacturer;
    const char *model;

    cstr_copy(param_list, config->param_list, sizeof(param_list));
    params_len = cstr_split(param_list, ",", params, ARRAY_SIZE(params));

    if(params_len < 4) {
        snprintf(err_msg, err_size, "%s模块参数配置错误", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    seconds = atoi(params[0]);
    sn = json_util_object_get_string(request, params[1]);
    manufacturer = json_util_object_get_string(request, params[2]);
    model = json_util_object_get_string(request, params[3]);

    if(cstr_empty(sn) || cstr_empty(manufacturer) || cstr_empty(model)) {
        snprintf(err_msg, err_size, "设备序列号、厂商、设备型号不能为空");
        dcs_log(0, 0, "at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,err_msg);
        return -1;
    }

    if(ctx->session == NULL) {
        ctx->session = create_session(ctx->shm);
        if(ctx->session == NULL) {
            //return send_http_error(outbuf, outsize, 500, "create session fail");
            json_object_object_add(response, "errcode", json_object_new_int(8));
            json_object_object_add(response, "errmsg", json_object_new_string("创建会话失败"));
            ret = -1;
        } else {
            bzero(ctx->session->remark, sizeof(ctx->session->remark));
            ctx->session->login_flag = '1';
            ctx->session->last_time = time(NULL);
            ctx->session->idle_time= seconds;
            gen_uuid((unsigned char *)ctx->session->key);
            snprintf(ctx->headers, ctx->headers_size, "Set-Cookie: suid=%s; path=/; HttpOnly\r\n"
                     "Set-Cookie: si=%d; path=/; HttpOnly\r\n",
                     ctx->session->key, ctx->session->ndx);

            session_attr_t *attr = (session_attr_t *)ctx->session->remark;
            cstr_copy(attr->attr1, sn, sizeof(attr->attr1));
            cstr_copy(attr->attr2, manufacturer, sizeof(attr->attr2));
            cstr_copy(attr->attr3, model, sizeof(attr->attr3));
        }
    }

    return ret;
}


struct execute_module my_check_module[] = {
    {"select_page", &module_select_page},
    {"select_one", &module_select_one},
    {"select_list", &module_select_list},
    {"insert", &module_insert},
    {"update", &module_update},
    {"delete", &module_delete},
    {"callproc", &module_callproc},
    {"copy", &module_copy},
    {"batch_select_one", &module_batch_select_one},
    {"batch_select_list", &module_batch_select_list},
    {"batch_select_column_list", &module_batch_select_column_list},
    {"batch_insert", &module_batch_insert},
    {"batch_update", &module_batch_update},
    {"batch_delete", &module_batch_delete},
    {"batch_callproc", &module_batch_callproc},
    {"batch_copy", &module_batch_copy},
    {"export_txt", &module_export_txt},
    {"export_xls", &module_export_xls},
    {"add", &module_add},
    {"check_sign", &module_check_sign},
    {"generate_tmk", &module_generate_tmk},
    {"generate_sign_key", &module_generate_sign_key},
    {"rsa_pk_encrypt", &module_rsa_pk_encrypt},
    {"generate_para_file", &module_generate_para_file},
    {"batch_generate_para_file", &module_batch_generate_para_file},
    {"extract_column_array", &module_extract_column_array},
    {"batch_execute", &module_batch_execute},
    {"create_session", &module_create_session},
    {"del", &module_del},
    {NULL,NULL}
};

module_fn search_execute_module(const char *module_name) {
    if(module_name == NULL)
        return NULL;

    int i = 0;

    while(my_check_module[i].module_name != NULL) {
        if(strcmp(my_check_module[i].module_name,module_name) == 0)
            break;
        i++;
    }
    return (my_check_module[i].module_name == NULL ? NULL : my_check_module[i].fn);
}

int execute_config(fun_config_t *config, process_ctx_t *ctx, json_object *request, json_object *response, char *err_msg, size_t err_size) {
    module_fn fn = search_execute_module(config->module_name);

    int ret;

    if(fn) {
        json_object *input = request;
        if(!cstr_empty(config->input)) {
            input = json_util_object_get(request, config->input);
        }

        ret = fn(config, ctx, input, response, err_msg, err_size);
    } else {
        ret = -1;
        snprintf(err_msg, err_size, "配置错误,没有该模块,module_name=%s", config->module_name);
        dcs_log(0, 0, "at %s(%s:%d) %.*s",__FUNCTION__,__FILE__,__LINE__, err_size, err_msg);
    }

    return ret;
}

static int select_fetch_fun_info_handler(void *ctx, oci_resultset_t *rs, int rownum) {
    fun_info_t *fun;

    fun = &g_fun_info[rownum-1];
    cstr_copy(fun->url, oci_get_string(rs, 1), sizeof(g_fun_info[0].url));
    cstr_copy(fun->op, oci_get_string(rs, 2), sizeof(g_fun_info[0].op));
    cstr_copy(fun->log_flag, oci_get_string(rs, 3), sizeof(g_fun_info[0].log_flag));

    return 1;
}

static int select_fetch_fun_config_handler(void *ctx, oci_resultset_t *rs, int rownum) {
    fun_config_t *config;

    config = &g_fun_config[rownum-1];
    cstr_copy(config->url, oci_get_string(rs, 1), sizeof(g_fun_config[0].url));
    cstr_copy(config->module_name, oci_get_string(rs, 2), sizeof(g_fun_config[0].module_name));
    cstr_copy(config->param_list, oci_get_string(rs, 3), sizeof(g_fun_config[0].param_list));
    cstr_copy(config->exec_type, oci_get_string(rs, 4), sizeof(g_fun_config[0].exec_type));
    cstr_copy(config->input, oci_get_string(rs, 5), sizeof(g_fun_config[0].input));
    cstr_copy(config->test, oci_get_string(rs, 6), sizeof(g_fun_config[0].test));


    return 1;
}



/**
*加载功能配置
*@param con 数据库连接
*@return 成功返回0,失败返回-1
*/
int load_fun_config(oci_connection_t *con) {
    int res = 0;
    char *sql;

    bzero(g_fun_info, sizeof(g_fun_info));
    g_fun_info_len = 0;

    bzero(g_fun_config, sizeof(g_fun_config));
    g_fun_config_len = 0;


    sql = "select url, op, log_flag from fun_info order by url";
    if((g_fun_info_len = sql_execute(con, sql, NULL, select_fetch_fun_info_handler, NULL, NULL, 0)) < 0) {
        res = -1;
    }

    if(res == 0) {
        sql = "select url, module_name, param_list, exec_type, input, test from fun_config a order by url, exec_type, order_no";
        if((g_fun_config_len = sql_execute(con, sql, NULL, select_fetch_fun_config_handler, NULL, NULL, 0)) < 0) {
            res = -1;
        }
    }

    return res;
}


//查找fun_info
int search_compare_fun_info(const void *k1, const void *k2) {
    char *url = (char *)k1;
    fun_info_t *d2= (fun_info_t *)k2;

    return strcmp(url, d2->url);
}


fun_info_t *search_fun_info(char *url) {
    return bsearch(url, g_fun_info, g_fun_info_len, sizeof(g_fun_info[0]), search_compare_fun_info);
}


//查找fun_config最小下标记录
int search_compare_fun_config_min(const void *k1, const void *k2) {
    int ret;
    char *url = (char *)k1;
    fun_config_t *d2= (fun_config_t *)k2;
    ret = strcmp(url, d2->url);
    if(ret == 0 && d2 > g_fun_config &&
       strcmp(d2[-1].url, d2[0].url) == 0) {
        ret = -1;
    }

    return ret;
}


fun_config_t *search_fun_config_min(char *url) {
    return bsearch(url, g_fun_config, g_fun_config_len, sizeof(g_fun_config[0]), search_compare_fun_config_min);
}

static int select_fetch_id_handler(void *ctx, oci_resultset_t *rs, int rownum) {
    process_ctx_t *pctx = (process_ctx_t *)ctx;
    cstr_copy(pctx->log_id, oci_get_string(rs, 1), sizeof(pctx->log_id));
    return 0; //终止fetch
}


int generate_log_id(process_ctx_t *ctx, char *err_msg, size_t err_size) {
    if(sql_execute(ctx->con, "select seq_log_id.nextval from dual", NULL, select_fetch_id_handler, ctx, err_msg, err_size) <= 0) {
        return -1; //出错
    }
    return 0; //成功
}

int write_oper_log(process_ctx_t *ctx, char *err_msg, int flag) {
    int res = 0;

    session_attr_t *attr = (session_attr_t *)ctx->session->remark;

    carray_t bind;

    carray_init(&bind, NULL);
    carray_append(&bind, ctx->log_id);
    carray_append(&bind, attr->attr1);
    carray_append(&bind, ctx->ip);
    carray_append(&bind, flag == 2 ? "1" : "0");
    carray_append(&bind, err_msg);

    if(sql_execute(ctx->con, "begin write_oper_log(:log_id, :login_name, :login_ip, :flag, :remark); end;", &bind, NULL, NULL, NULL, 0) < 0) {
        res = -1;
    }
    carray_destory(&bind);

    return res;
}


void process_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    oci_connection_t *con = ctx->con;
    fun_info_t *fun;
    fun_config_t *config;
    int i, first_trans, second_trans, log_trans, config_len;

    char err_msg[MAX_ERR_MSG_SIZE] = {0};
    size_t err_size = sizeof(err_msg);

    fun = search_fun_info(ctx->action);
    config = search_fun_config_min(ctx->action);

    if(fun == NULL || config == NULL) {
        //没有功能配置
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("没有功能配置"));
    } else {
        //操作类型/日志标志
        cstr_copy(ctx->op, fun->op, sizeof(ctx->op));
        cstr_copy(ctx->log_flag, fun->log_flag, sizeof(ctx->log_flag));

        first_trans = 1;

        //生成日志ID
        if(strcmp(ctx->log_flag, "1") == 0) {
            if(generate_log_id(ctx, err_msg, err_size) != 0) {
                first_trans = 0;
                json_object_object_add(response, "errcode", json_object_new_int(8));
                json_object_object_add(response, "errmsg", json_object_new_string("生成日志id出错"));
            }
        }

        if(first_trans == 1) {
            //计算长度
            config_len = 0;
            while(config+config_len < g_fun_config+g_fun_config_len &&
                  strcmp(config[config_len].url, config[0].url) == 0)
                config_len ++;

            //事务1
            for(i = 0;  i < config_len ; i ++) {
                if(config[i].exec_type[0] != '0') {
                    break;
                } else {
                    if(execute_config(config+i, ctx, request, response, err_msg, err_size) != 0) {
                        db_errmsg_trans(err_msg, err_size);

                        if(json_util_object_get_int(response, "errcode") == 0) {
                            json_object_object_add(response, "errcode", json_object_new_int(8));
                        }

                        if(json_util_object_get(response, "errmsg") == NULL) {
                            json_object_object_add(response, "errmsg", json_object_new_string(err_msg));
                        }
                        //事务失败
                        first_trans = 0;
                        break;
                    }
                }
            }

            if(!first_trans) {
                //失败回滚
                oci_rollback(con);

                //跳过业务事务
                for(; i < config_len; i ++) {
                    if(config[i].exec_type[0] != '0') {
                        break;
                    }
                }
            }

            second_trans = 1;
            //事务2
            for(; i < config_len; i ++) {
                if(execute_config(config+i, ctx, request, response, err_msg, err_size) != 0) {
                    //事务失败
                    second_trans = 0;
                    break;
                }
            }

            if(!second_trans) {
                //失败回滚
                oci_rollback(con);
            }

            //写日志
            log_trans = 1;
            if(strcmp(ctx->log_flag, "1") == 0) {
                if(write_oper_log(ctx, err_msg, first_trans+second_trans) != 0) {
                    log_trans = 0;
                    oci_rollback(con);
                    json_object_object_add(response, "errcode", json_object_new_int(8));
                    json_object_object_add(response, "errmsg", json_object_new_string("写日志出错"));
                }
            }

            if(log_trans == 1) {
                //commit可能失败
                if(oci_commit(con) == FALSE) {
                    json_object_object_add(response, "errcode", json_object_new_int(8));
                    json_object_object_add(response, "errmsg", json_object_new_string("数据库commit出错"));
                }
            }
        }
    }
}

const int gifsize;
void captcha(unsigned char im[70*200], unsigned char l[6]);
void makegif(unsigned char im[70*200], unsigned char gif[gifsize]);


int send_http_error(char *outbuf, int outsize, int code, const char *fmt, ...);

int captcha_handler(process_ctx_t *ctx, connection *con, int *flag, char *outbuf, int outsize) {
    //创建会话
    int headers_len = 0;

    headers_len = snprintf(outbuf, outsize,
                           "HTTP/1.1 200 OK\r\n"
                           "Cache-Control: no-cache\r\n"
                           "Content-Type: image/jpeg\r\n"
                           "Content-Length: %d\r\n",  gifsize);

    if(ctx->session == NULL) {
        ctx->session = create_session(ctx->shm);
        if(ctx->session == NULL) {
            return send_http_error(outbuf, outsize, 500, "create session fail");
        }
        //重置
        bzero(ctx->session->remark, sizeof(ctx->session->remark));
        ctx->session->login_flag = '1';
        ctx->session->last_time = time(NULL);
        ctx->session->idle_time=3600;
        gen_uuid((unsigned char *)ctx->session->key);
        headers_len += snprintf(outbuf+headers_len, outsize-headers_len, "Set-Cookie: suid=%s; path=/; http-only\r\n"
                                "Set-Cookie: si=%d; path=/; HttpOnly\r\n",
                                ctx->session->key, ctx->session->ndx);
        //dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__, ctx->session->key);
    }

    headers_len += snprintf(outbuf+headers_len, outsize-headers_len, "\r\n");

    //发送图片文件
    {
        unsigned char l[6];
        unsigned char im[70*200];
        unsigned char gif[gifsize];
        char filepath[1024];
        int fd;

        captcha(im,l);
        makegif(im,gif);

        snprintf(filepath, sizeof(filepath), "/tmp/%ld-%d.out", (long)getpid(),con->fd);

        if((fd = open(filepath, O_WRONLY | O_TRUNC | O_CREAT, 0644)) < 0) {

        } else {
            write(fd, gif, gifsize);
            close(fd);
            send_file2(con->fd, flag, filepath, 0, -1);
        }

        strcpy(ctx->session->remark+2, (char *)l);
    }



    return headers_len;
}

int check_session(process_ctx_t *ctx) {
    //会话检查
    if(ctx->session == NULL) {
        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__, "无效会话");
        return -1;
    }

    session_attr_t *attr = (session_attr_t *)ctx->session->remark;

    //更新最后访问时间
    ctx->session->last_time = time(NULL);

    return 0;
}


void action_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    //dcs_debug(0, 0, "at %s(%s:%d) ctx[%p]",__FUNCTION__, __FILE__, __LINE__, ctx);
#if 0
    int ret;

    if(check_session(ctx) != 0) {
        json_object_object_add(response, "errcode", json_object_new_int(-11));
        json_object_object_add(response, "errmsg", json_object_new_string("非法会话,请重新登录"));
    } else {
        //ctx->session->last_time = time(NULL);
        //功能权限检查
        ret = check_function_acl(ctx);
        if(ret == 1) {
            json_object_object_add(response, "errcode", json_object_new_int(-12));
            json_object_object_add(response, "errmsg", json_object_new_string("请重置密码"));
        } else if(ret != 0) {
            json_object_object_add(response, "errcode", json_object_new_int(-12));
            json_object_object_add(response, "errmsg", json_object_new_string("没有功能权限"));
        } else {
            //ctx->request = request;
#endif
            process_handler(ctx, request, response);
#if 0
        }
    }
#endif
}

