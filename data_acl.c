#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "base.h"

#include "json.h"
#include "cdefs.h"
#include "cstr.h"
#include "cbuf.h"
#include "carray.h"
#include "ocilib.h"
#include "sql.h"
#include "data_acl.h"
#include "action_handler.h"


struct data_rule_s {
    int data_rule_id;
    char res_code[32+1];
    char op[1+1];
    json_object *data_rule;
};

typedef struct data_rule_s data_rule_t;

data_rule_t g_data_rule[1024];
int g_data_rule_len = 0;


static json_object *json_util_object_get(json_object* obj, const char *key) {
    struct json_object *result = NULL;
    json_object_object_get_ex(obj, key, &result);
    return result;
}


static const char *json_util_object_get_string(json_object* obj, const char *key) {
    json_object *result = json_util_object_get(obj, key);
    return json_object_get_string(result);
}

static int search_compare_data_rule(const void *k1, const void *k2) {
    int res;
    int *v1 = (int *)k1;
    data_rule_t *v2 = (data_rule_t *)k2;
    res = *v1 - v2->data_rule_id;
    return res;
}

static data_rule_t *search_data_rule(int data_rule_id) {
    return bsearch(&data_rule_id, g_data_rule, g_data_rule_len,
                   sizeof(g_data_rule[0]), search_compare_data_rule);
}

static void gen_rule_where(void *ctx, cbuf_t *buf, json_object *rule, char *alias, int lo_flag) {
    const char *field = json_util_object_get_string(rule, "field");
    const char *op = json_util_object_get_string(rule, "op");
    const char *value = json_util_object_get_string(rule, "value");
    const char *lo = json_util_object_get_string(rule, "lo");

    char a[32];
    bzero(a, sizeof(a));
    if(!cstr_empty(alias)) {
        snprintf(a, sizeof(a), "%s.", alias);
    }
    alias = a;

    if(strcmp(op, "in") == 0) {
        cbuf_printf(buf, "%s%s %s (%s)", alias, field, op, value);
    } else if(strcmp(op, "like") == 0) {
        cbuf_printf(buf, "%s%s %s '%%'||'%s'||'%%'", alias, field, op, value);
    } else if(strcmp(op, "exists") == 0 || strcmp(op, "not exists") == 0) {
        cbuf_printf(buf, "%s (%s)", op, value);
    } else {
        cbuf_printf(buf, "%s%s %s %s", alias, field, op, value);
    }

    if(lo_flag) {
        cbuf_printf(buf, " %s ", lo);
    }
}


static void gen_group_where(void *ctx, cbuf_t *buf, json_object *rules, const char *lo, char *alias, int lo_flag) {
    int flag = 1, i, len;
    len = json_object_array_length(rules);

    cbuf_append(buf, "(", 1);
    for(i = 0; i < len; i++) {
        if(i == len - 1) {
            flag = 0;
        }

        json_object *rule = json_object_array_get_idx(rules, i);
        const char *tag = json_util_object_get_string(rule, "tag");

        if(tag == NULL || strcmp(tag, "rule") == 0) {
            gen_rule_where(ctx, buf, rule, alias, flag);
        } else if(strcmp(tag, "group") == 0) {
            json_object *group_rules =  json_util_object_get(rule, "rules");
            const char *group_lo = json_util_object_get_string(rule, "lo");
            gen_group_where(ctx, buf, group_rules, group_lo, alias, flag);
        }
    }

    cbuf_append(buf, ")", 1);


    if(lo_flag) {
        cbuf_printf(buf, " %s ", lo);
    }
}

extern oci_connection_t *get_connection(void *ctx);
extern char *get_current_value(void *data, const char *name);


struct data_acl_s {
    int role_id;
    int data_rule_id;
};

typedef struct data_acl_s data_acl_t;

#define MAX_DATA_ACL_SIZE 32


static int select_fetch_data_acl_handler(void *ctx, oci_resultset_t *rs, int rownum) {

    data_acl_t *acl = (data_acl_t *)ctx;

    //最多32条记录
    if(rownum > MAX_DATA_ACL_SIZE) {
        return -1;
    }

    acl[rownum-1].role_id = oci_get_int(rs, 1);
    acl[rownum-1].data_rule_id = oci_get_int(rs, 2);

    return 1;
}


int gen_data_acl(sql_ctx_t *ctx, char *res_code, char *alias, cbuf_t *buf) {
    int res = 0, flag, i, len, acl_len;
	data_acl_t acl[MAX_DATA_ACL_SIZE];
	
	data_rule_t *data_rule;
    json_object *rules;
	
    process_ctx_t *pro_ctx = (process_ctx_t *)ctx->data;
	char *userid = get_current_value(pro_ctx, "CurrentUserID");
	char *sql = "select a.role_id, b.data_rule_id from (select role_id from data_role start with role_id in (select role_id from user_data_role where userid=:userid) connect by prior role_pid = role_id) a,data_role_rule b,data_rule c where a.role_id = b.role_id and b.data_rule_id = c.data_rule_id and c.res_code = :res_code order by a.role_id,c.op desc";
    
    //dcs_debug(0, 0, "at %s(%s:%d) [%s]",__FUNCTION__,__FILE__,__LINE__, userid);

	carray_t bind;
    carray_init(&bind, NULL);

    carray_append(&bind, userid);
    carray_append(&bind, res_code);

    if((acl_len = sql_execute(pro_ctx->con, sql, &bind, select_fetch_data_acl_handler, acl, NULL, 0)) < 0) {
        res = -1;
    }

    carray_destory(&bind);

    if(res == 0) {
		flag = 0;
        for(i = 0; i < acl_len; i++) {
            if(i > 0 && acl[i].role_id != acl[i-1].role_id) {
                flag = 0;
            }

            data_rule = search_data_rule(acl[i].data_rule_id);
            if(data_rule == NULL) {
                res = -1;
                break;
            } else if(strcmp(data_rule->op, pro_ctx->op) == 0) {
                rules = data_rule->data_rule;
                len = json_object_array_length(rules);
                if(len > 0) {
                    cbuf_append(buf, " and ", 5);
                    gen_group_where(ctx, buf, rules, NULL, alias, 0);
                }
                flag = 1;
            } else if(flag == 0 && strcmp(data_rule->op, "*") == 0) {
                rules = data_rule->data_rule;
                len = json_object_array_length(rules);
                if(len > 0) {
                    cbuf_append(buf, " and ", 5);
                    gen_group_where(ctx, buf, rules, NULL, alias, 0);
                }
            }
        }
    }

	//c_error("%s", cbuf_str(buf));

    return res;
}

static int select_fetch_data_rule_handler(void *ctx, oci_resultset_t *rs, int rownum) {
    data_rule_t *rule;
    rule = &g_data_rule[rownum-1];	
    rule->data_rule_id = oci_get_int(rs, 1);
    cstr_copy(rule->res_code, oci_get_string(rs, 2), sizeof(rule->res_code));
    cstr_copy(rule->op, oci_get_string(rs, 3), sizeof(rule->res_code));
    rule->data_rule = json_tokener_parse(oci_get_string(rs, 4));

    return 1;
}


int load_data_rule(oci_connection_t *con) {
    int res = 0;
    char *sql = "select data_rule_id, res_code, op, data_rule from data_rule order by data_rule_id";

    bzero(g_data_rule, sizeof(g_data_rule));
    g_data_rule_len = 0;

    if((g_data_rule_len = sql_execute(con, sql, NULL, select_fetch_data_rule_handler, NULL, NULL, 0)) < 0) {
        res = -1;
    }

    return res;
}

