#include <stdio.h>
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

#include "ocilib.h"
#include "exp.h"
#include "sql.h"
#include "action_handler.h"


void register_checking_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    dcs_debug(0, 0, "at %s(%s:%d)", __FUNCTION__, __FILE__, __LINE__);
    char err_msg[MAX_ERR_MSG_SIZE] = {0};
    size_t err_size = sizeof(err_msg);
    const char *login_name = json_util_object_get_string(request, "login_name");
    const char *login_pwd = json_util_object_get_string(request, "login_pwd");
    const char *img_captcha = json_util_object_get_string(request, "captcha");
    const char *full_name = json_util_object_get_string(request, "full_name");
    const char *mobile = json_util_object_get_string(request, "mobile");
	const char *mcht_no = json_util_object_get_string(request, "mcht_no");

    if(ctx->session == NULL || cstr_empty(img_captcha) || strcmp(ctx->session->remark+2, img_captcha) != 0) {
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("验证码错误"));
        return;
    } else if(cstr_empty((char *)login_name) || cstr_empty((char *)login_pwd)) {
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("用户名或密码不能为空"));
        dcs_log(0, 0, "用户名或密码不能为空 %s %s", login_name, login_pwd);
        return;
    } else if(strlen(json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN)) > 500) {
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("数据太大"));
        return;
    }

    carray_t bind;

    carray_init(&bind, NULL);
    carray_append(&bind, (char *)login_name);
    carray_append(&bind, (char *)login_pwd);
    carray_append(&bind, (char *)full_name);
    carray_append(&bind, (char *)mobile);
	carray_append(&bind, (char *)mcht_no);

    if(sql_execute(ctx->con, "begin register_checking(:login_name,:login_pwd,:full_name,:mobile,:mcht_no); end;", &bind, NULL, NULL, err_msg, err_size) < 0) {
        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,err_msg);
		oci_rollback(ctx->con);
        db_errmsg_trans(err_msg, err_size);
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string(err_msg));
    } else {
        //保存用户信息
        strcpy(ctx->session->remark+10, json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN)); //保留前10byte

        ctx->session->remark[1] = '3'; //注册等待验证
    }
    carray_destory(&bind);

    ctx->session->remark[2] = '\0'; //重置验证码
}


int required(const char *value, const char *name, json_object *response) {
	char buf[100];
	if(cstr_empty(value)){
		snprintf(buf, sizeof(buf), "%s不能为空", name);
		json_object_object_add(response, "errcode", json_object_new_int(8));
    	json_object_object_add(response, "errmsg", json_object_new_string(buf));
		return -1;
	}
	return 0;
}


void register_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    dcs_debug(0, 0, "at %s(%s:%d)", __FUNCTION__, __FILE__, __LINE__);
    char err_msg[MAX_ERR_MSG_SIZE] = {0};
    size_t err_size = sizeof(err_msg);

    const char *mobile = json_util_object_get_string(request, "mobile");
	const char *login_pwd = json_util_object_get_string(request, "login_pwd");
	const char *captcha = json_util_object_get_string(request, "captcha");

	if(required(mobile, "手机号", response) != 0 
		|| required(login_pwd, "密码", response) != 0
		|| required(captcha, "验证码", response) != 0) {
		return;
	}

    carray_t bind;

    carray_init(&bind, NULL);
	carray_append(&bind, (char *)mobile);
	carray_append(&bind, (char *)login_pwd);
    carray_append(&bind, (char *)captcha);
    

    if(sql_execute(ctx->con, "begin register_user(:mobile,:login_pwd,:captcha); end;", &bind, NULL, NULL, err_msg, err_size) < 0) {
        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,err_msg);
		oci_rollback(ctx->con);
        db_errmsg_trans(err_msg, err_size);
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string(err_msg));
    }
    carray_destory(&bind);
}


void sms_captcha_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    dcs_debug(0, 0, "at %s(%s:%d)", __FUNCTION__, __FILE__, __LINE__);
    char err_msg[MAX_ERR_MSG_SIZE] = {0};
    size_t err_size = sizeof(err_msg);

    const char *mobile = json_util_object_get_string(request, "mobile");

    if(required(mobile, "手机号", response) != 0) {
		return;
	}

    carray_t bind;

    carray_init(&bind, NULL);
    carray_append(&bind, (char *)mobile);

    if(sql_execute(ctx->con, "begin sms_captcha(:mobile); end;", &bind, NULL, NULL, err_msg, err_size) < 0) {
        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,err_msg);
		oci_rollback(ctx->con);
        db_errmsg_trans(err_msg, err_size);
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string(err_msg));
    }
    carray_destory(&bind);
}



void reset_pwd_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    dcs_debug(0, 0, "at %s(%s:%d)", __FUNCTION__, __FILE__, __LINE__);
    char err_msg[MAX_ERR_MSG_SIZE] = {0};
    size_t err_size = sizeof(err_msg);

    const char *mobile = json_util_object_get_string(request, "mobile");
	const char *new_login_pwd = json_util_object_get_string(request, "new_login_pwd");
	const char *captcha = json_util_object_get_string(request, "captcha");

	if(required(mobile, "手机号", response) != 0 
		|| required(new_login_pwd, "新密码", response) != 0
		|| required(captcha, "验证码", response) != 0) {
		return;
	}

    carray_t bind;

    carray_init(&bind, NULL);
	carray_append(&bind, (char *)mobile);
	carray_append(&bind, (char *)new_login_pwd);
    carray_append(&bind, (char *)captcha);
    

    if(sql_execute(ctx->con, "begin user_reset_pwd(:mobile,:new_login_pwd,:captcha); end;", &bind, NULL, NULL, err_msg, err_size) < 0) {
        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,err_msg);
		oci_rollback(ctx->con);
        db_errmsg_trans(err_msg, err_size);
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string(err_msg));
    }
    carray_destory(&bind);
}



void generate_random(char *buf, int buf_size) {
	static const char *numbers="0123456789abcdefghijklmnopqrstuvwxyz";
	int i;
	if(buf_size <= 0) {
		return;
	}
	for(i = 0; i < buf_size - 1; i++) {
		buf[i] = numbers[rand()%36];
	}
	buf[i] = '\0';
}


void session_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
	if(ctx->session == NULL) {
		ctx->session = create_session(ctx->shm);
		if(ctx->session == NULL) {
			//return send_http_error(outbuf, outsize, 500, "create session fail");
			json_object_object_add(response, "errcode", json_object_new_int(8));
        	json_object_object_add(response, "errmsg", json_object_new_string("创建会话失败"));
			return;
		}
		//重置
		bzero(ctx->session->remark, sizeof(ctx->session->remark));
		ctx->session->login_flag = '1';
		ctx->session->last_time = time(NULL);
		ctx->session->idle_time=3600;
		gen_uuid((unsigned char *)ctx->session->key);
		snprintf(ctx->headers, ctx->headers_size, "Set-Cookie: suid=%s; path=/; HttpOnly\r\n"
								"Set-Cookie: si=%d; path=/; HttpOnly\r\n",
								ctx->session->key, ctx->session->ndx);
	}

	char random_num[7];
	generate_random(random_num, sizeof(random_num));

	json_object_object_add(response, "captcha", json_object_new_string(random_num));
}


void login_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    dcs_debug(0, 0, "at %s(%s:%d)", __FUNCTION__, __FILE__, __LINE__);
    int rc = -1, ret = 0, count = -1;
    char err_msg[MAX_ERR_MSG_SIZE] = {0};
    size_t err_size = sizeof(err_msg);
    const char *login_name = json_util_object_get_string(request, "login_name");
    const char *login_pwd = json_util_object_get_string(request, "login_pwd");
    const char *captcha = json_util_object_get_string(request, "captcha");
	
	if(ctx->session == NULL) {
		json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("无效会话"));
        return;
	}

	session_attr_t *attr = (session_attr_t *)ctx->session->remark;

    if(cstr_empty(captcha) || strcmp(attr->img_captcha, captcha) != 0) {
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("验证码错误"));
        return;
    } else if(cstr_empty((char *)login_name) || cstr_empty((char *)login_pwd)) {
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("用户名或密码不能为空"));
        dcs_log(0, 0, "用户名或密码不能为空 %s %s", login_name, login_pwd);
        return;
    }

    carray_t bind;
    carray_init(&bind, NULL);
    carray_append(&bind, (char *)login_name);

    ret = sql_execute(ctx->con, "select a.userid,a.login_name,a.login_pwd,a.status,a.login_type,a.inst_id,a.user_level,regexp_replace(a.mobile, '(\\S{3})\\S*(\\S{4})', '\\1****\\2') mobile,a.last_login_time,sysdate,a.last_login_ip,a.province,a.city,a.district,b.attr1,b.attr2,b.attr3,b.attr4,b.attr5 from userinfo a,inst_info b where login_name=:login_name and a.inst_id=b.inst_id(+)", &bind, select_fetch_row_handler, response, err_msg, err_size);

    carray_destory(&bind);

    dcs_debug(0, 0, "at %s(%s:%d) %d ", __FUNCTION__, __FILE__, __LINE__,ret);

    if(ret != 1) {
        //用户名错误
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("用户名或密码错误"));

        dcs_log(0, 0, "用户名错误 %s,%s", login_name, err_msg);
    } else {
        const char *userid2 = json_util_object_get_string(response, "userid");
        const char *status2 = json_util_object_get_string(response, "status");
        const char *login_pwd2 = json_util_object_get_string(response, "login_pwd");
        const char *login_type2 = json_util_object_get_string(response, "login_type");
        const char *inst_id2 = json_util_object_get_string(response, "inst_id");
        const char *user_level2 = json_util_object_get_string(response, "user_level");
        const char *last_login_time2 = json_util_object_get_string(response, "last_login_time");
        const char *sysdate2 = json_util_object_get_string(response, "sysdate");
        const char *last_login_ip2 = json_util_object_get_string(response, "last_login_ip");
		const char *province2 = json_util_object_get_string(response, "province");
		const char *city2 = json_util_object_get_string(response, "city");
		const char *district2 = json_util_object_get_string(response, "district");
		const char *attr1 = json_util_object_get_string(response, "attr1");
		const char *attr2 = json_util_object_get_string(response, "attr2");
		const char *attr3 = json_util_object_get_string(response, "attr3");
		const char *attr4 = json_util_object_get_string(response, "attr4");
		const char *attr5 = json_util_object_get_string(response, "attr5");

		

        //验证密码
        char buf[33];
        md5(buf, login_pwd2, attr->img_captcha, 0);

        carray_init(&bind, NULL);
        carray_append(&bind, (char *)userid2);

        if(sql_execute(ctx->con, "begin before_login(:userid); end;", &bind, NULL, NULL, err_msg, err_size) < 0) {
			oci_rollback(ctx->con);
            db_errmsg_trans(err_msg, err_size);
            json_object_object_add(response, "errcode", json_object_new_int(8));
            json_object_object_add(response, "errmsg", json_object_new_string(err_msg));
        } else if(strcmp(buf, login_pwd) != 0) {
            json_object_object_add(response, "errcode", json_object_new_int(8));
            json_object_object_add(response, "errmsg", json_object_new_string("用户名或密码错误"));
            dcs_log(0, 0, "密码错误 %s %s", buf, login_pwd);
        } else if(status2[0] != '1') {
            json_object_object_add(response, "errcode", json_object_new_int(8));
            json_object_object_add(response, "errmsg", json_object_new_string("用户已禁用"));
            dcs_log(0, 0, "用户已禁用 %s", login_name);
        } else if(sql_execute(ctx->con, "select count(1) total from user_data_role where userid=:userid", &bind, select_fetch_count_handler, &count, NULL, 0) <= 0) {
            json_object_object_add(response, "errcode", json_object_new_int(8));
            json_object_object_add(response, "errmsg", json_object_new_string("用户没有数据角色"));
            dcs_log(0, 0, "用户没有数据权限 %s", userid2);
        } else {
            ctx->session->last_time = time(NULL);

            //存储会话属性
            cstr_copy(attr->userid, userid2, sizeof(attr->userid));
            cstr_copy(attr->login_name, login_name, sizeof(attr->login_name));
            cstr_copy(attr->inst_id, inst_id2, sizeof(attr->inst_id));
            cstr_copy(attr->user_level, user_level2, sizeof(attr->user_level));
            cstr_copy(attr->login_type, login_type2, sizeof(attr->login_type));
			cstr_copy(attr->province, province2, sizeof(attr->province));
			cstr_copy(attr->city, city2, sizeof(attr->city));
			cstr_copy(attr->district, district2, sizeof(attr->district));
			cstr_copy(attr->attr1, attr1, sizeof(attr->attr1));
			cstr_copy(attr->attr2, attr2, sizeof(attr->attr2));
			cstr_copy(attr->attr3, attr3, sizeof(attr->attr3));
			cstr_copy(attr->attr4, attr4, sizeof(attr->attr4));
			cstr_copy(attr->attr5, attr5, sizeof(attr->attr5));
			
            if(attr->login_type[0] == '0') { //密码验证方式
            	attr->session_flag = '1'; //会话生效
            } else {
            	attr->session_flag = '2'; //会话等待验证
            }

            //一天同一IP只要验证一次
            char *login_mode = getenv("LOGIN_MODE");
            if(!cstr_empty(login_mode) && strcmp(login_mode,"1") == 0) {
                if(strncmp(last_login_time2, sysdate2, 10) == 0 &&
                   strcmp(last_login_ip2, ctx->ip) == 0) {
                    attr->session_flag = '1'; //会话生效
                    json_object_object_add(response, "login_type", json_object_new_string("0")); //转为密码验证方式
                }
            }

			rc = 0;
        }

        carray_append(&bind, ctx->ip);
        carray_append(&bind, rc == 0 ? "1" : "0");
        carray_append(&bind, attr->session_flag == '1' ? "1" : "0");
        if(sql_execute(ctx->con, "begin after_login(:userid, :login_ip, :flag, :session_flag); end;", &bind, NULL, NULL, err_msg, err_size) < 0) {
			oci_rollback(ctx->con);
            db_errmsg_trans(err_msg, err_size);
            json_object_object_add(response, "errcode", json_object_new_int(8));
            json_object_object_add(response, "errmsg", json_object_new_string(err_msg));
        }
        carray_destory(&bind);
    }

    json_object_object_del(response, "login_pwd");
    json_object_object_del(response, "sysdate");

    attr->img_captcha[0] = '\0'; //重置验证码
}


void login_captcha_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    dcs_debug(0, 0, "at %s(%s:%d)", __FUNCTION__, __FILE__, __LINE__);
    char err_msg[MAX_ERR_MSG_SIZE] = {0};
    size_t err_size = sizeof(err_msg);

    const char *order_no = json_util_object_get_string(request, "order_no");

	if(ctx->session == NULL) {
		json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("无效会话"));
        return;
	}

	session_attr_t *attr = (session_attr_t *)ctx->session->remark;

    if(attr->session_flag != '2') {
        json_object_object_add(response, "errcode", json_object_new_int(-11));
        json_object_object_add(response, "errmsg", json_object_new_string("无效会话,请先登录"));
        return;
    }

    carray_t bind;

    carray_init(&bind, NULL);
    carray_append(&bind, attr->userid);
    carray_append(&bind, (char *)order_no);

    if(sql_execute(ctx->con, "begin generate_captcha(:userid, :order_no); end;", &bind, NULL, NULL, err_msg, err_size) < 0) {
        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,err_msg);
		oci_rollback(ctx->con);
        db_errmsg_trans(err_msg, err_size);
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string(err_msg));
    }

    carray_destory(&bind);
}


void login_verify_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    dcs_debug(0, 0, "at %s(%s:%d)", __FUNCTION__, __FILE__, __LINE__);
    char err_msg[MAX_ERR_MSG_SIZE] = {0};
    size_t err_size = sizeof(err_msg);

    const char *captcha = json_util_object_get_string(request, "captcha");

    if(ctx->session == NULL) {
		json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("无效会话"));
        return;
	}

	session_attr_t *attr = (session_attr_t *)ctx->session->remark;

    if(attr->session_flag != '2' || cstr_empty(captcha)) {
        //dcs_debug(ctx->session->remark, 2, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,captcha);
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string("验证码错误"));
        return;
    }

    carray_t bind;

    carray_init(&bind, NULL);
    carray_append(&bind, attr->userid);
    carray_append(&bind, ctx->ip);
    carray_append(&bind, (char *)captcha);

    if(sql_execute(ctx->con, "begin verify_captcha(:userid, :login_ip, :captcha); end;", &bind, NULL, NULL, err_msg, err_size) < 0) {
        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,err_msg);
		oci_rollback(ctx->con);
        db_errmsg_trans(err_msg, err_size);
        json_object_object_add(response, "errcode", json_object_new_int(8));
        json_object_object_add(response, "errmsg", json_object_new_string(err_msg));
    } else {
        attr->session_flag = '1'; //登录成功,会话生效
    }
    carray_destory(&bind);
}


void logout_handler(process_ctx_t *ctx, json_object *request, json_object *response) {
    if(ctx->session) {
        del_session(ctx->shm, ctx->session->ndx, ctx->session->key);
    }
}


typedef void (*custom_fn)(process_ctx_t *ctx, json_object *request, json_object *response);


struct custom_module {
    char *action;
    custom_fn fn;
};

struct custom_module my_custom_module[] = {
    //{"/action/user/register-checking", &register_checking_handler},
    {"/action/user/reg", &register_handler},
    {"/action/user/login", &login_handler},
    //{"/action/user/login-captcha", &login_captcha_handler},
    //{"/action/user/login-verify", &login_verify_handler},
    {"/action/user/logout", &logout_handler},
	{"/action/user/sms-captcha", &sms_captcha_handler},
	{"/action/user/reset-pwd", &reset_pwd_handler},
	{"/action/user/session", &session_handler},
    {NULL,NULL}
};

custom_fn search_custom_module(const char *module_name) {
    if(module_name == NULL)
        return NULL;

    int i = 0;

    while(my_custom_module[i].action != NULL) {
        if(strcmp(my_custom_module[i].action,module_name) == 0)
            break;
        i++;
    }
    return (my_custom_module[i].action == NULL ? NULL : my_custom_module[i].fn);
}


int custom_handler(process_ctx_t *ctx, json_object *request, json_object *response) {

    custom_fn caller = search_custom_module(ctx->action);
    if(caller) {
        caller(ctx, request, response);
        return 0;
    }

    return -1;
}

