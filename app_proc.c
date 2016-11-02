#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <iconv.h>
#include <uuid/uuid.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ibdcs.h"
#include "base.h"
#include "http_parse.h"
#include "frame.h"
#include "secuLib_wst.h"

#include "json.h"
#include "json_ext.h"

#include "cdefs.h"
#include "cstr.h"
#include "ciconv.h"
#include "cbin.h"
#include "cdes.h"
#include "cmd5.h"

#include "ocilib.h"
#include "sql.h"


#include "data_acl.h"
#include "action_handler.h"
#include "custom_handler.h"
#include "http_util.h"


#define MAX_PATH_SIZE 1024
#define MAX_BUFFER_SIZE 4096
#define DEFAULT_DIR_MODE (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)


char *document_root, *g_db, *g_db_user, *g_db_pwd, *g_db_pwd_mode;
oci_connection_t *g_db_con;


static const char *ajax_response_json = "HTTP/1.1 200 OK\r\n"
                                        "Cache: no-cache\r\n"
                                        "Content-Type: application/json\r\n";

#if 0
static const char *ajax_response_text = "HTTP/1.1 200 OK\r\n"
                                        "Cache: no-cache\r\n"
                                        "Content-Type: text/plain\r\n";
#endif

static int reload_flag = 0, reconnect_flag = 0;


static void signal_handler(int signum) {
    if(signum == SIGUSR1) {
        reload_flag = 1;
    }
}

#if 0
size_t code_convert(const char *from_charset, const char *to_charset, char *inbuf, size_t inlen,
                    char *outbuf, size_t outlen) {
    iconv_t cd;
    int rc;
    char **pin = &inbuf;
    char **pout = &outbuf;
    size_t len_out = outlen;

    if(from_charset == NULL || to_charset == NULL || inbuf == NULL || outbuf == NULL) {
        dcs_log(0, 0, "<FILE:%s,LINE:%d><code_convert> return fail.", __FILE__, __LINE__);
        return -1;
    }

    cd = iconv_open(to_charset, from_charset);

    if(cd == (iconv_t)(-1)) {
        dcs_log(0, 0, "<FILE:%s,LINE:%d><code_convert>call iconv_open return failure.", __FILE__,
                __LINE__);
        return -1;
    }
    //dcs_log(inbuf,inlen,"<FILE:%s,LINE:%d><code_convert>%s",__FILE__,__LINE__,strerror(errno));
    memset(outbuf, 0, outlen);
    if((rc = iconv(cd, pin, &inlen, pout, &len_out)) == -1) {
        //dcs_log(0,0,"<FILE:%s,LINE:%d><code_convert>call iconv return failure.%s\n%.*s",__FILE__,__LINE__,strerror(errno),inlen, inbuf);
        dcs_log(0, 0, "<FILE:%s,LINE:%d><code_convert>call iconv return failure.%s", __FILE__,
                __LINE__, strerror(errno));
        iconv_close(cd);
        return -1;
    }
    iconv_close(cd);
    return outlen - len_out;
}

//GB2312码转为UTF-8码
int GBKToUTF8(char *inbuf, size_t inlen, char *outbuf, size_t outlen) {
    //"ISO8859-2"
    return code_convert("GBK", "UTF-8", inbuf, (size_t) inlen, outbuf, (size_t) outlen);
}

//UTF-8码转为GB2312码
int UTF8ToGBK(char *inbuf, size_t inlen, char *outbuf, size_t outlen) {
    //"ISO8859-2"
    return code_convert("UTF-8", "GBK", inbuf, (size_t) inlen, outbuf, (size_t) outlen);
}
#endif

static const char *status_code_to_str(int status_code) {
    switch(status_code) {

        case 100:
            return "Continue";
        case 101:
            return "Switching Protocols";
        case 102:
            return "Processing";

        case 200:
            return "OK";
        case 201:
            return "Created";
        case 202:
            return "Accepted";
        case 203:
            return "Non-Authoritative Information";
        case 204:
            return "No Content";
        case 205:
            return "Reset Content";
        case 206:
            return "Partial Content";
        case 207:
            return "Multi-Status";
        case 208:
            return "Already Reported";
        case 226:
            return "IM Used";

        case 300:
            return "Multiple Choices";
        case 301:
            return "Moved Permanently";
        case 302:
            return "Found";
        case 303:
            return "See Other";
        case 304:
            return "Not Modified";
        case 305:
            return "Use Proxy";
        case 306:
            return "Switch Proxy";
        case 307:
            return "Temporary Redirect";
        case 308:
            return "Permanent Redirect";

        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 402:
            return "Payment Required";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 406:
            return "Not Acceptable";
        case 407:
            return "Proxy Authentication Required";
        case 408:
            return "Request Timeout";
        case 409:
            return "Conflict";
        case 410:
            return "Gone";
        case 411:
            return "Length Required";
        case 412:
            return "Precondition Failed";
        case 413:
            return "Payload Too Large";
        case 414:
            return "URI Too Long";
        case 415:
            return "Unsupported Media Type";
        case 416:
            return "Requested Range Not Satisfiable";
        case 417:
            return "Expectation Failed";
        case 418:
            return "I\'m a teapot";
        case 422:
            return "Unprocessable Entity";
        case 423:
            return "Locked";
        case 424:
            return "Failed Dependency";
        case 426:
            return "Upgrade Required";
        case 428:
            return "Precondition Required";
        case 429:
            return "Too Many Requests";
        case 431:
            return "Request Header Fields Too Large";
        case 451:
            return "Unavailable For Legal Reasons";

        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 502:
            return "Bad Gateway";
        case 503:
            return "Service Unavailable";
        case 504:
            return "Gateway Timeout";
        case 505:
            return "HTTP Version Not Supported";
        case 506:
            return "Variant Also Negotiates";
        case 507:
            return "Insufficient Storage";
        case 508:
            return "Loop Detected";
        case 510:
            return "Not Extended";
        case 511:
            return "Network Authentication Required";

        default:
            return "Server Error";
    }
}


int send_http_error(char *outbuf, int outsize, int code, const char *fmt, ...) {
    const char *message = status_code_to_str(code);
    char body[200];
    int body_len, headers_len;
    va_list ap;

    body_len = snprintf(body, sizeof(body), "%d %s\n", code, message);
    if(fmt != NULL) {
        va_start(ap, fmt);
        body_len += vsnprintf(body + body_len, sizeof(body) - body_len, fmt, ap);
        va_end(ap);
    }

    headers_len = snprintf(outbuf, outsize, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n"
                           "Content-Type: text/plain\r\n\r\n", code, message, body_len);
    memcpy(outbuf+headers_len, body, body_len);

    return headers_len + body_len;
}





static int send_buf_data(int sock, char *buf, int len) {
    int n, nwrite = 0;
    while(nwrite < len) {
        n = send(sock, buf+nwrite, len-nwrite, 0);
        if(n == -1) {
            if(errno == EAGAIN) {
                n = 0;
            } else {
                break;
            }
        }
        nwrite += n;
    }

    if(nwrite < len) {
        //error
        dcs_log(0,0,"at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__, strerror(errno));
        return -1;
    }
    return 0;
}



int get_cookie(struct mg_request_info *ri, const char *cookie_name, char *dst, size_t dst_size) {
    const char *s, *p, *end;
    int name_len, len = -1;
    dst[0] = '\0';
    if((s = get_header(ri, "Cookie")) == NULL) {
        return -1;
    }

    name_len = (int) strlen(cookie_name);
    end = s + strlen(s);
    for(; (s = strstr(s, cookie_name)) != NULL; s += name_len) {
        if(s[name_len] == '=') {
            s += name_len + 1;
            if((p = strchr(s, ' ')) == NULL)
                p = end;
            if(p[-1] == ';')
                p--;
            if(*s == '"' && p[-1] == '"' && p > s + 1) {
                s++;
                p--;
            }
            if((size_t)(p - s) < dst_size) {
                len = p - s;
                cstr_copy(dst, s, (size_t) len + 1);
            }
            break;
        }
    }
    return len;
}


session *get_my_session(shm_data *ptr, char *ndx, char *key) {
    session *psession = NULL;

#if 0

    char *ip = getenv("SESSION_IP");
    char *port = getenv("SESSION_PORT");

    if(ip == NULL || port == NULL) {
        dcs_log(0,0,"at %s(%s:%d) 环境变量SESSION_IP或SESSION_PORT没有配置", __FUNCTION__,__FILE__,__LINE__);
        return NULL;
    }

    char errmsg[512];
    msg_pack_t pack;

    bzero(errmsg, sizeof(errmsg));
    bzero(&pack, sizeof(pack));
    strcpy_s(pack.session_id, key, sizeof(pack.session_id));
    strcpy_s(pack.session_idx, ndx, sizeof(pack.session_idx));
    if(get_remote_session(ip, atoi(port), &pack, errmsg, sizeof(errmsg)) != 0) {
        dcs_log(0,0,"at %s(%s:%d) 读取远程会话存储失败,%s",__FUNCTION__,__FILE__,__LINE__,errmsg);
    } else {
        if(!strcmp(pack.code, "00")) {
            //存储到本地
            psession = (session *)pack.data;

            memcpy(ptr->ptr+psession->ndx, psession, sizeof(*psession));

            psession = ptr->ptr+psession->ndx;
        }
    }
#endif
    psession = get_session(ptr, atoi(ndx), key);

    return psession;
}


int url_decode(const char *src, int src_len, char *dst,
               int dst_len, int is_form_url_encoded) {
    int i, j, a, b;
#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

    for(i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
        if(src[i] == '%' && i < src_len - 2 &&
           isxdigit(* (const unsigned char *)(src + i + 1)) &&
           isxdigit(* (const unsigned char *)(src + i + 2))) {
            a = tolower(* (const unsigned char *)(src + i + 1));
            b = tolower(* (const unsigned char *)(src + i + 2));
            dst[j] = (char)((HEXTOI(a) << 4) | HEXTOI(b));
            i += 2;
        } else if(is_form_url_encoded && src[i] == '+') {
            dst[j] = ' ';
        } else {
            dst[j] = src[i];
        }
    }

    dst[j] = '\0'; // Null-terminate the destination

    return i >= src_len ? j : -1;
}


void form_decode(char *buf, json_object *request) {
    char *var[128];
    int i, var_num;
    var_num = cstr_split(buf, "&", var, ARRAY_SIZE(var));

    for(i = 0; i < var_num; i++) {
        char *pair[2];
        int num = cstr_split(var[i], "=", pair, ARRAY_SIZE(pair));
        if(num == 2) {
            char value[1024];
            url_decode(pair[1], strlen(pair[1]), value, sizeof(value), 1);

            json_object_object_add(request, pair[0], json_object_new_string(value));
        }
    }
}

typedef int (*upload_success_callback)(int sock_id, char *file_name ,char *file_path, long off_set,char *remark);


static int parse_header(const char *str, int str_len, const char *var_name,
                        char *buf, size_t buf_size) {
    int ch = ' ', len = 0, n = strlen(var_name);
    const char *p, *end = str + str_len, *s = NULL;

    if(buf != NULL && buf_size > 0) buf[0] = '\0';

    // Find where variable starts
    for(s = str; s != NULL && s + n < end; s++) {
        if((s == str || s[-1] == ' ' || s[-1] == ',') && s[n] == '=' &&
           !memcmp(s, var_name, n)) break;
    }

    if(s != NULL && &s[n + 1] < end) {
        s += n + 1;
        if(*s == '"' || *s == '\'') ch = *s++;
        p = s;
        while(p < end && p[0] != ch && p[0] != ',' && len < (int) buf_size) {
            if(p[0] == '\\' && p[1] == ch) p++;
            buf[len++] = *p++;
        }
        if(len >= (int) buf_size || (ch != ' ' && *p != ch)) {
            len = 0;
        } else {
            if(len > 0 && s[len - 1] == ',') len--;
            if(len > 0 && s[len - 1] == ';') len--;
            buf[len] = '\0';
        }
    }

    return len;
}

//包括\n
static int get_line_len(const char *buf, int buf_len) {
    int len = 0;
    while(len < buf_len && buf[len] != '\n') len++;
    return buf[len] == '\n' ? len + 1: -1;
}

int parse_multipart(const char *buf, int buf_len,
                    char *var_name, int var_name_len,
                    char *file_name, int file_name_len,
                    const char **data, int *data_len) {
    static const char cd[] = "Content-Disposition: ";
    //struct mg_connection c;
    int hl, bl, n, ll, pos, cdl = sizeof(cd) - 1;
    //char *p;

    if(buf == NULL || buf_len <= 0) return -1;
    if((hl = get_request_len(buf, buf_len)) <= 0) return -1;
    if(buf[0] != '-' || buf[1] != '-' || buf[2] == '\r') return -1;

    // Get boundary length
    bl = get_line_len(buf, buf_len);

    // Loop through headers, fetch variable name and file name
    var_name[0] = file_name[0] = '\0';
    for(n = bl; (ll = get_line_len(buf + n, hl - n)) > 0; n += ll) {
        if(strncasecmp(cd, buf + n, cdl) == 0) {
            parse_header(buf + n + cdl, ll - (cdl + 2), "name",
                         var_name, var_name_len);
            parse_header(buf + n + cdl, ll - (cdl + 2), "filename",
                         file_name, file_name_len);
        }
    }

    if(data != NULL) *data = buf+hl;
    if(data_len != NULL) *data_len = 0; //文件大小可能是0
    // Scan body, search for terminating boundary
    for(pos = hl; pos + (bl - 2) < buf_len; pos++) {
        if(buf[pos] == '-' && !memcmp(buf, &buf[pos], bl - 2)) {
            if(data_len != NULL)
                *data_len = (pos - 2) - hl;
            return pos;
        }
    }

    return 0;
}


static int mkdirs(const char *dir, mode_t mode) {
    int ret = 0;
    char copy_dir[MAX_PATH_SIZE];
    char *p = copy_dir;

    if(dir[0] == '\0')
        return -1;

    cstr_copy(copy_dir, dir, sizeof(copy_dir));

    while((p = strchr(p+1, '/')) != NULL) {
        *p = '\0';
        ret = mkdir(copy_dir, mode);
        *p = '/';
        if(ret != 0 && errno != EEXIST) {
            dcs_debug(0,0,"at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,strerror(errno));
            return -1;
        }
    }

    ret = mkdir(copy_dir, mode);

    if(ret != 0 && errno != EEXIST) {
        dcs_debug(0,0,"at %s(%s:%d) %s",__FUNCTION__,__FILE__,__LINE__,strerror(errno));
        return -1;
    }

    return 0;
}


void get_ip(struct mg_request_info *ri, process_ctx_t *ctx) {
    struct in_addr client_ip;
    const char *agent_ip = NULL;
    if((agent_ip = get_header(ri, "X-Forwarded-For")) != NULL) {
        char *p = strchr(agent_ip, ',');
        if(p == NULL) {
            cstr_copy(ctx->ip, agent_ip, sizeof(ctx->ip));
        } else {
            cstr_copy(ctx->ip, agent_ip, (p - agent_ip) < sizeof(ctx->ip) ? (p - agent_ip)+1 : sizeof(ctx->ip));
        }
    } else {
        client_ip.s_addr = htonl(ri->remote_ip);
        cstr_copy(ctx->ip, inet_ntoa(client_ip), sizeof(ctx->ip));
    }
}


static void decrypt_db_pwd(char *db_pwd, char *buf, size_t buf_size) {
    int i;
    unsigned char temp[256+1];
    unsigned char ciphertext[128+1];
    unsigned char plaintext[128+1];
    unsigned char key[128+1] = "2SWqhYC41BGCNKBJg4sRJGaWDL/C78C5EzoGFDCBYtGM64G1Mn/oCQkDBmmaay53yCIJDRlWfwtwuky63I9Wf3oIAXxQNMfob4oJWaYnFweaE7L1BhFPLWbxl5uTV5HC";

    bzero(temp, sizeof(temp));
    bzero(ciphertext, sizeof(ciphertext));
    bzero(plaintext, sizeof(plaintext));

    cstr_copy((char *)temp, db_pwd, sizeof(temp));
    cbin_hex_to_bin(temp, ciphertext, 256);

    for(i = 0; i < 128; i +=8) {
        cdes_decrypt(ciphertext+i, plaintext+i, key+i);
    }

    cstr_copy(buf, (char *)plaintext, buf_size);
}


static int reconnect() {
    char db_pwd[256+1];
    reconnect_flag = 0;

    oci_connection_free(g_db_con);

    bzero(db_pwd, sizeof(db_pwd));
    if(strcmp(g_db_pwd_mode, "1") == 0) {
        decrypt_db_pwd(g_db_pwd, db_pwd, sizeof(db_pwd));
    } else {
        cstr_copy(db_pwd, g_db_pwd, sizeof(db_pwd));
    }
    if((g_db_con = oci_connection_new(g_db, g_db_user, db_pwd)) == NULL) {
        dcs_log(0, 0, "at %s(%s:%d) 重新连接数据库,oci_connection_new失败", __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    return 0;
}

static int reload_config(oci_connection_t *con) {
    reload_flag = 0;
    sql_destroy();
    if(sql_init(con) != 0) {
        dcs_log(0, 0, "at %s(%s:%d) 重新加载配置,初始化SQL库失败", __FUNCTION__, __FILE__, __LINE__);
        return -1;
    } else {
        dcs_log(0, 0, "at %s(%s:%d) 重新加载配置,初始化SQL库成功", __FUNCTION__, __FILE__, __LINE__);
    }

    if(load_fun_config(con) != 0) {
        dcs_log(0, 0, "at %s(%s:%d) 重新加载配置,缓存功能配置数据失败", __FUNCTION__, __FILE__, __LINE__);
        return -1;
    } else {
        dcs_log(0, 0, "at %s(%s:%d) 重新加载配置,缓存功能配置数据成功", __FUNCTION__, __FILE__, __LINE__);
    }

    if(load_data_rule(con) != 0) {
        dcs_log(0, 0, "at %s(%s:%d) 重新加载配置成功,缓存数据权限数据失败", __FUNCTION__, __FILE__, __LINE__);
        return -1;
    } else {
        dcs_log(0, 0, "at %s(%s:%d) 重新加载配置,缓存数据权限数据成功", __FUNCTION__, __FILE__, __LINE__);
    }

    return 0;
}

int test_databse_connection(oci_connection_t *con) {
    sql_execute(con, TEST_DATABSE_SQL, NULL, NULL, NULL, NULL, 0);
    if(reconnect_flag == 1) {
        if(reconnect() != 0) {
            return -1;
        }
    }

    return 0;
}


static void remove_double_dots(char *s) {
    char *p = s;

    while(*s != '\0') {
        *p++ = *s++;
        if(s[-1] == '/' || s[-1] == '\\') {
            while(s[0] != '\0') {
                if(s[0] == '/' || s[0] == '\\') {
                    s++;
                } else if(s[0] == '.' && s[1] == '.') {
                    s += 2;
                } else {
                    break;
                }
            }
        }
    }
    *p = '\0';
}


static void uri_to_path(struct mg_request_info *hm, char *buf, size_t buf_len) {
    char uri[MAX_PATH_SIZE];

    url_decode(hm->uri, strlen(hm->uri), uri, sizeof(uri), 0);
    remove_double_dots(uri);
    snprintf(buf, buf_len, "%s%s", document_root, uri);
}


void send_file2(int fd, int *flag, const char *path, long offset, long file_size) {
    JOB job;

    memset(&job, 0, sizeof(job));
    job.off_set = offset;
    job.file_size = file_size;
    job.sock_id = fd;
    job.read_or_write = 1; // 0写 1读

    const char *p = strrchr(path, '/');
    if(p == NULL) {
        p = path;
    } else {
        p++;
    }

    snprintf(job.file_path, sizeof(job.file_path), "%.*s", (int)(p-path-1), path);
    snprintf(job.file_name, sizeof(job.file_name), "%s", p);

    dcs_log(0, 0, "at %s(%s:%d) [%s][%s]", __FUNCTION__, __FILE__, __LINE__,
            job.file_path, job.file_name);

    job_working(&job, NULL, 0);


    *flag = 1;
}

int send_file(connection *con, void *shm_ptr, int *flag, char *outbuf, int outsize, struct mg_request_info *hm, process_ctx_t *ctx) {
    char filepath[MAX_PATH_SIZE];
    struct stat st;

    uri_to_path(hm, filepath, sizeof(filepath));
    dcs_debug(0, 0, "at %s(%s:%d) [%s]", __FUNCTION__, __FILE__, __LINE__,filepath);

    if(stat(filepath, &st)) {
        dcs_log(0, 0, "at %s(%s:%d) 404 Not Found,%s,%s", __FUNCTION__, __FILE__, __LINE__,strerror(errno), filepath);
        return send_http_error(outbuf, outsize, 404, "Not Found");
    }

	char custom_headers[200];
	int headers_offset = 0;
	bzero(custom_headers, sizeof(custom_headers));
	
    //计算文件MD5
    {
        session_attr_t *attr = (session_attr_t *)ctx->session->remark;

        //取签名key
        int n = 0;

        char err_msg[MAX_ERR_MSG_SIZE];
        size_t err_size = sizeof(err_msg);

        char sign_sek_indx[5+1];
        char sign_key[256+1];

        bzero(err_msg, sizeof(err_msg));

        memset(sign_sek_indx, ' ', sizeof(sign_sek_indx));
        sign_sek_indx[sizeof(sign_sek_indx)-1] = '\0';

        memset(sign_key, ' ', sizeof(sign_key));
        sign_key[sizeof(sign_key)-1] = '\0';

        carray_t bind;
        carray_init(&bind, NULL);
        carray_append(&bind, attr->attr1);
        carray_append(&bind, attr->attr2);
        carray_append(&bind, attr->attr3);
        carray_append(&bind, sign_sek_indx);
        carray_append(&bind, sign_key);

        if(sql_execute(ctx->con, "begin get_sign_key(:sn,:manufacturer,:model,:sign_sek_indx,:sign_key); end;", &bind, NULL, NULL, err_msg, err_size) < 0) {
            dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,err_msg);
            oci_rollback(ctx->con);
            db_errmsg_trans(err_msg, err_size);
            n = send_http_error(outbuf, outsize, 500, err_msg);
        }

        carray_destory(&bind);

        if(n > 0) {
            return n;
        }

        cstr_rtrim(sign_sek_indx);
        cstr_rtrim(sign_key);

        char buf[MAX_BUFFER_SIZE];
        size_t nread;
        FILE *fp = fopen(filepath, "r");

        cmd5_ctx_t md5;
        cmd5_init(&md5);
        while((nread = fread(buf, 1, sizeof(buf), fp)) > 0) {
            cmd5_update(&md5, (unsigned char *)buf, nread);
        }
        cmd5_digest(&md5, (unsigned char *)buf);

		dcs_log(buf, 16, "md5[%s]", filepath);

        char return_code[4];

        char sign_key_data[16];
        char ciphertext[16];
        int ciphertext_len;
		char ciphertext_hex[33];

        cbin_hex_to_bin((unsigned char *)sign_key, (unsigned char *)sign_key_data, strlen(sign_key));

        DES3(return_code, sign_sek_indx, sign_key_data, 16, buf, &ciphertext_len, ciphertext);
		dcs_log(ciphertext, 16, "ciphertext");

		bzero(ciphertext_hex, sizeof(ciphertext_hex));
		cbin_bin_to_hex((unsigned char *)ciphertext, (unsigned char *)ciphertext_hex, 16);

		headers_offset += snprintf(custom_headers+headers_offset, sizeof(custom_headers)-headers_offset, "Content-MD5: %s\r\n", ciphertext_hex);
    }

    if(!cstr_empty(hm->query_string)) {
        http_pairs_t query;
        net_parse_http_query_string(hm->query_string, hm->query_string+strlen(hm->query_string), &query);
        net_str_t *filename = net_get_http_query_string(&query, "filename");

        if(filename != NULL) {
            snprintf(custom_headers+headers_offset, sizeof(custom_headers)-headers_offset, "Content-Disposition: attachment; filename=%.*s\r\n", (int)filename->len, filename->p);
        }
    }

    int64_t offset = 0, len = 0;
    int n = net_send_http_file2(&st, get_header(hm, "Range"), custom_headers, outbuf, outsize, &offset, &len);


    dcs_debug(0, 0, "at %s(%s:%d)\n%.*s", __FUNCTION__, __FILE__, __LINE__,n,outbuf);

    /*
    int status_code = 200;
    char *msg = "OK";
    int n = snprintf(outbuf, outsize,
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: application/octet-stream\r\n"
                     "Content-Length: %ld\r\n"
                     "%s"
                     "\r\n", status_code, msg, st.st_size, custom_headers);
    */

    if(len > 0) {
        send_file2(con->fd, flag, filepath, offset, offset + len);
    }

    return n;
}



int do_get(connection *con, void *shm_ptr, int *flag, char *outbuf, int outsize, struct mg_request_info *hm, process_ctx_t *ctx) {

    if(strcmp(hm->uri, "/action/user/captcha") == 0) {
        return captcha_handler(ctx, con, flag, outbuf, outsize);
    }

    if(check_session(ctx) != 0) {
        //error
        return send_http_error(outbuf, outsize, 500, "非法会话");
    }

    return send_file(con, shm_ptr, flag, outbuf, outsize, hm, ctx);
}

int do_head(connection *con, void *shm_ptr, int *flag, char *outbuf, int outsize, struct mg_request_info *hm, process_ctx_t *ctx) {
    char filepath[MAX_PATH_SIZE];
    struct stat st;

    uri_to_path(hm, filepath, sizeof(filepath));
    dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,filepath);

    if(stat(filepath, &st)) {
        dcs_log(0, 0, "at %s(%s:%d) 404 Not Found,%s", __FUNCTION__, __FILE__, __LINE__,filepath);
        return send_http_error(outbuf, outsize, 404, "Not Found");
    }

    int status_code = 200;
    char *status_message = "OK";

    int n = snprintf(outbuf, outsize,
                     "HTTP/1.1 %d %s\r\n"
                     "Accept-Ranges: bytes\r\n"
                     "Content-Type: application/octet-stream\r\n"
                     "Content-Length: %" INT64_FMT
                     "\r\n"
                     "\r\n",
                     status_code, status_message, st.st_size);
    dcs_debug(0, 0, "at %s(%s:%d) %.*s", __FUNCTION__, __FILE__, __LINE__,n, outbuf);
    return n;
}



int request_handler(int fd, int *flag, char *outbuf, int outsize, process_ctx_t *ctx, json_object *request, json_object *response) {
    char headers[200];
    bzero(headers, sizeof(headers));

    json_object_object_add(response, "errcode", json_object_new_int(0)); //默认值

    ctx->headers = headers;
    ctx->headers_size = sizeof(headers);

    if(custom_handler(ctx, request, response) == 0) {
        //已经处理
    } else {
        action_handler(ctx, request, response);
    }

    if(json_util_object_get_int(response, "errcode") != 0) {
        json_object_object_add(response, "rows", json_object_new_array()); //适配分页查询
    }

    const char *body = json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN);
    int body_len = strlen(body);

    int headers_len = snprintf(outbuf, outsize, "%s%sContent-Length: %d\r\n\r\n",
                               ajax_response_json, headers, body_len);

    if(headers_len+body_len <= outsize) {
        memcpy(outbuf + headers_len, body, body_len);
        //json_object_put(response); //free
        return headers_len + body_len;
    }

    //文件方式返回数据
    char filepath[MAX_PATH_SIZE];

    snprintf(filepath, sizeof(filepath), "/tmp/%ld-%d.out", (long)getpid(), fd);

    json_object_to_file(filepath, response);
    //json_object_put(response); //free

    send_file2(fd, flag, filepath, 0, -1);
    return headers_len;
}

int on_begin_proc(int sock_id, int fd, char  *file_name,char  *file_path,char *cache_buf,char *file_cache, char *remark,long *off_set, long *file_size,void *buf,int buf_len) {
    //dcs_debug(buf,buf_len,"at %s(%s:%d) %d %d %d",__FUNCTION__,__FILE__,__LINE__,sock_id,fd, buf_len);
    write(fd, buf, buf_len);
    return 1;
}

int on_end_proc(int sock_id, char *file_name ,char *file_path, long off_set,char *remark) {
    int flag = 0;
    process_ctx_t ctx;
    char filepath[MAX_PATH_SIZE];
    char outbuf[MAX_BUFFER_SIZE];
    int n;

    memcpy(&ctx, remark, sizeof(ctx));
    //snprintf(filepath, sizeof(filepath), "/tmp/%ld-%d.in", (long)getpid(), sock_id);
    snprintf(filepath, sizeof(filepath), "%s/%s", file_path, file_name);

    json_object *request = json_object_from_file(filepath);
    json_object *response = json_object_new_object();
    n = request_handler(sock_id, &flag, outbuf, sizeof(outbuf), &ctx, request, response);

    send_buf_data(sock_id, outbuf, n); //阻塞

    json_object_put(request);
    json_object_put(response);

    return 1;
}



//大数据请求,文件方式处理
void big_request(connection *con, int *flag, process_ctx_t *ctx) {
    JOB job;
    bzero(&job, sizeof(job));

    snprintf(job.file_path, sizeof(job.file_path), "/tmp");
    snprintf(job.file_name, sizeof(job.file_name), "%ld-%d.in", (long)getpid(),con->fd);

    //上传文件方式
    job.sock_id = con->fd;
    job.read_or_write = 2; // 0写 1读 2文件方式
    job.off_set = con->data_len-con->head_len;
    job.file_size = con->msg_len - (con->data_len-con->head_len);
    job.begin_proc = on_begin_proc;
    job.end_proc = on_end_proc;

    if(ctx != NULL) {
        memcpy(job.remark, ctx, sizeof(*ctx)); //process_ctx_t大小不能超过512
        job.remark_len = sizeof(*ctx);
    }

    job_working(&job, con->buf+con->head_len, job.off_set);

    *flag = 1; //不断连接
}

json_object* json_parse(const char *str, int len) {
    json_tokener* tok;
    json_object* obj;

    tok = json_tokener_new();
    if(!tok)
        return NULL;
    obj = json_tokener_parse_ex(tok, str, len);
    if(tok->err != json_tokener_success) {
        if(obj != NULL)
            json_object_put(obj);
        obj = NULL;
		dcs_debug((char *)str, len, "at %s(%s:%d)\n%s", __FUNCTION__, __FILE__, __LINE__,json_tokener_error_desc(tok->err));
    }

    json_tokener_free(tok);
    return obj;
}


int upload_error_caller(int sock_id, char *file_name ,char *file_path, long off_set, char *remark) {
    json_object *response;
    char buf[MAX_BUFFER_SIZE];
    const char *body;
    int body_len, len;

    response = json_object_new_object();
    json_object_object_add(response, "errcode", json_object_new_int(8));
    json_object_object_add(response, "errmsg", json_object_new_string("upload file error"));

    body = json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN);
    body_len = strlen(body);


    len = snprintf(buf, sizeof(buf),
                   "%sContent-Length: %d\r\n\r\n%s", ajax_response_json, body_len, body);

    json_object_put(response);

    send_buf_data(sock_id, buf, len); //阻塞

    return 1;
}

int upload_success_caller(int sock_id, char *file_name ,char *file_path, long off_set,char *remark) {
    int flag = 0;
    process_ctx_t *ctx;
    char filepath[MAX_PATH_SIZE];
    char outbuf[MAX_BUFFER_SIZE];
    int n;

    ctx = (process_ctx_t *)remark;
    //snprintf(filepath, sizeof(filepath), "/tmp/%ld-%d.in", (long)getpid(), sock_id);
    snprintf(filepath, sizeof(filepath), "%s/%s", file_path, file_name);

    json_object *request = ctx->user_data1;
    json_object *response = json_object_new_object();

    dcs_debug(0, 0, "%s", json_object_to_json_string(request));

    json_object_object_add(request, "url", json_object_new_string(filepath+strlen(document_root)));

    n = request_handler(sock_id, &flag, outbuf, sizeof(outbuf), ctx, request, response);

    send_buf_data(sock_id, outbuf, n); //阻塞

    if(json_util_object_get_int(response, "errcode") != 0) {
        remove(filepath);
    }

    json_object_put(request);
    json_object_put(response);

    ctx->user_data1 = NULL;

    return 1;
}


void get_current_date(char *str, size_t str_size) {
    time_t tt;
    struct tm local_time;

    time(&tt);
    localtime_r(&tt, &local_time);
    strftime(str, str_size, "%Y%m%d", &local_time);
}


int uploadfile(connection *con, void *shm_ptr, int *flag, char *outbuf, int outsize, struct mg_request_info *hm, process_ctx_t *ctx) {
    char dest_dir[MAX_PATH_SIZE];
    char today[20];

    char *content = (char *)con->buf+con->head_len;
    int content_len = con->data_len-con->head_len;

    int offset = 0;
    const char *data;
    int data_len;
    char var_name[MAX_PATH_SIZE], file_name[MAX_PATH_SIZE];

    get_current_date(today, sizeof(today));
    snprintf(dest_dir, sizeof(dest_dir), "%s/%s/%s", document_root, "files", today);

    for(;;) {
        int n;
        if((n = parse_multipart(content+offset, content_len-offset,
                                var_name, sizeof(var_name),
                                file_name, sizeof(file_name),
                                &data, &data_len)) < 0) {
            break;
        }

        dcs_debug(0,0,"at %s(%s:%d) %d[%s][%s]",__FUNCTION__,__FILE__,__LINE__,
                  n, var_name, file_name);

        if(strlen(file_name) > 0) { //进入解析
            char *t = strrchr(file_name, '/');
            if(t == NULL)
                t = file_name;

            char *s = strrchr(t, '.');
            if(s == NULL)
                s = "";

            char file[MAX_PATH_SIZE], name[MAX_PATH_SIZE];

            //srand((int)time(0));
            unsigned char uuid_buf[33];
            gen_uuid(uuid_buf);

            snprintf(name, sizeof(name), "%s%s", uuid_buf, s);
            snprintf(file, sizeof(file), "%s/%s", dest_dir, name);

            struct stat st;

            if(!(stat(file, &st) == -1 && errno == ENOENT)) {
                //文件已经存在
                dcs_debug(0,0,"at %s(%s:%d) file exists[%s]",__FUNCTION__,__FILE__,__LINE__,
                          file);
                break;
            }

            mkdirs(dest_dir, DEFAULT_DIR_MODE); //创建目录

            FILE *fp = fopen(file, "wb");
            if(fp == NULL) {
                break;
            }

            if(n == 0) {
                int hl = get_request_len(content, content_len);
                int bl = get_line_len(content, hl);

                JOB job;
                memset(&job, 0, sizeof(job));

                fwrite(data, content+content_len-data, 1, fp);
                fclose(fp);
                //copy to cache_buf
                if(content+content_len-data-bl-2 > 0) {
                    memcpy(job.cache_buf, content+content_len-bl-2,bl+2);
                } else {
                    memcpy(job.cache_buf+bl+2-(content+content_len-data), data, content+content_len-data);
                }

                job.sock_id = con->fd;
                job.read_or_write = 0; // 0写 1读

                strncpy(job.file_head, content, bl-2);
                strcpy(job.file_name, name);
                strcpy(job.file_path, dest_dir);
                job.off_set = content+content_len-data;

                job.end_proc = upload_success_caller;
                job.error_proc = upload_error_caller;

                if(ctx != NULL) {
                    memcpy(job.remark, ctx, sizeof(*ctx)); //process_ctx_t大小不能超过512
                    job.remark_len = sizeof(*ctx);
                }

                dcs_debug(0,0,"at %s(%s:%d) [%s][%s][%s]",__FUNCTION__,__FILE__,__LINE__,
                          job.file_head,job.file_name,job.file_path);

                job_working(&job, NULL, 0);

                *flag = 1; //不断连接
            } else {
                fwrite(data, data_len, 1, fp);
                fclose(fp);
                upload_success_caller(con->fd, name, dest_dir, 0, NULL);
            }


            return 0; //end
        }
        offset += n;
    }

    return send_http_error(outbuf, outsize, 500, "upload file fail");
}



int do_post(connection *con, void *shm_ptr, int *flag, char *outbuf, int outsize, struct mg_request_info *hm, process_ctx_t *ctx) {

    dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__, "entry");

    const char *content_type = get_header(hm, "Content-Type");
    int n = 0;

    if(content_type == NULL) {
        return send_http_error(outbuf, outsize, 501, NULL);
    } else if(strstr(content_type, "application/json") != NULL) {
        if(con->data_len < con->head_len + con->msg_len) {
            big_request(con, flag, ctx);
        } else {
            json_object *request = json_parse((char *)con->buf + con->head_len, con->msg_len);
            json_object *response = json_object_new_object();
            n = request_handler(con->fd, flag, outbuf, outsize,ctx, request, response);
            json_object_put(request); //free
            json_object_put(response); //free

            dcs_debug(0, 0, "at %s(%s:%d)\n%.*s", __FUNCTION__, __FILE__, __LINE__, n, outbuf);
        }
    } else if(strstr(content_type, "multipart/form-data") != NULL) {
        ctx->user_data1 = json_object_new_object();
        if(!cstr_empty(hm->query_string)) {
            http_pairs_t query;
            net_parse_http_query_string(hm->query_string, hm->query_string+strlen(hm->query_string), &query);

            char key[DEFAULT_BUFFER_SIZE];
            int i;

            for(i = 0; i < ARRAY_SIZE(query.keys); i++) {
                net_str_t *k = &query.keys[i], *v = &query.values[i];
                if(k->p != NULL) {
                    bzero(key, sizeof(key));
                    memcpy(key, k->p, MIN(sizeof(key)-1,k->len));
                    json_object_object_add(ctx->user_data1, key, json_object_new_string_len(v->p, v->len));
                }
            }
        }
        return uploadfile(con, shm_ptr, flag, outbuf, outsize, hm, ctx);
    } else {
        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__, content_type);
        return send_http_error(outbuf, outsize, 501, NULL);
    }

    return n;
}



int app_proc(connection *con, void *shm_ptr, int *flag, char *outbuf, int outsize) {
    //dcs_debug(0, 0, "at %s(%s:%d)", __FUNCTION__, __FILE__, __LINE__);

    if(con->type == 3) {
        //测试数据库连接
        if(test_databse_connection(g_db_con) != 0) {
            return send_http_error(outbuf, outsize, 500, "Database connection failed", NULL);
        }

        //重新加载配置
        if(reload_flag == 1) {
            if(reload_config(g_db_con) != 0) {
                return send_http_error(outbuf, outsize, 500, "reload config failed", NULL);
            }
        }

        //con->head_len http报文头长度
        //con->msg_len 报文头Content-Length的值
        //con->data_len 收到的数据大小(<=16k)
        dcs_debug(0, 0, "at %s(%s:%d) head_len=%d msg_len=%d data_len=%d", __FUNCTION__, __FILE__, __LINE__,
                  con->head_len, con->msg_len, con->data_len);

        dcs_debug(con->buf, con->data_len, "at %s(%s:%d)\n%.*s", __FUNCTION__, __FILE__, __LINE__, con->data_len, con->buf);

        struct mg_request_info hm;
        int headers_len;
        char *p;

        //解析http
        //获取headers长度
        headers_len = con->head_len;
        if(headers_len > 0) {
            con->buf[headers_len - 1] = '\0';
        }

        if(parse_http_request((char *)con->buf, &hm) < 0) {
            dcs_log(0, 0, "at %s(%s:%d) parse_http_request 解析HTTP出错", __FUNCTION__, __FILE__, __LINE__);
            return send_http_error(outbuf, outsize, 500, "parse http headers fail");
        }

        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,hm.uri);

        hm.query_string = NULL;
        if((p = strchr(hm.uri, '?')) != NULL) { //query_string问题
            *p = '\0';
            hm.query_string = p + 1;
        }

        dcs_debug(0, 0, "at %s(%s:%d) %s", __FUNCTION__, __FILE__, __LINE__,hm.uri);

        process_ctx_t ctx;
        bzero(&ctx, sizeof(ctx));

        ctx.con = g_db_con;
        get_ip(&hm, &ctx);
        ctx.shm = shm_ptr;
        ctx.session = NULL;
        cstr_copy(ctx.action, hm.uri, sizeof(ctx.action));
        ctx.sign = get_header(&hm, "Content-MD5");
        ctx.body = (char *)con->buf+headers_len;
        ctx.body_len = con->data_len - headers_len;


        //取session
        char suid[100], si[100];
        if(get_cookie(&hm, "suid", suid, sizeof(suid)) > 0
           && get_cookie(&hm, "si", si, sizeof(si)) > 0) {
            ctx.session = get_my_session((shm_data *) shm_ptr, si, suid);
            //dcs_debug(0, 0, "at %s(%s:%d) %s %s %p", __FUNCTION__, __FILE__, __LINE__, si, suid, ctx.session);
        }

        if(strcmp(hm.request_method, "GET") == 0) {
            return do_get(con, shm_ptr, flag, outbuf, outsize, &hm, &ctx);
        } else if(strcmp(hm.request_method, "HEAD") == 0) {
            return do_head(con, shm_ptr, flag, outbuf, outsize, &hm, &ctx);
        } else if(strcmp(hm.request_method, "POST") == 0) {
            return do_post(con, shm_ptr, flag, outbuf, outsize, &hm, &ctx);
        } else {
            return send_http_error(outbuf, outsize, 501, NULL);
        }
    }

    return 0;
}

void sql_error_handler(oci_error_t *err) {
    int code = oci_get_error_code(err);
    oci_statement_t *stmt = oci_get_error_stmt(err);

    if(code == -3114 || code == -3113 || code == -3135 ||
       code == 3114 || code == 3113 || code == 3135) {
        reconnect_flag = 1;
    }

    if(code == 1403 && oci_get_stmt_type(stmt) == OCI_ST_SELECT &&
       oci_get_row_count(stmt) > 0) {
        //nothing
    } else {
        dcs_log(0, 0, "at %s(%s:%d) %d %d\n%s", __FUNCTION__, __FILE__, __LINE__,code,oci_get_error_warning(err),oci_get_error_msg(err));
    }
}



int app_init(server *srv) {
    //char *path; //环境变量路径
    char db_pwd[256+1];

    dcs_log(0, 0, "初始化中...");

    if(signal(SIGUSR1, signal_handler) == SIG_ERR) {
        dcs_log(0, 0, "at %s(%s:%d) signal SIGUSR1 error", __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    document_root = getenv("DOCUMENT_ROOT");
    if(cstr_empty(document_root)) {
        dcs_log(0, 0, "at %s(%s:%d) 没有配置环境变量DOCUMENT_ROOT", __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    g_db = getenv("DB");
    if(cstr_empty(g_db)) {
        dcs_log(0, 0, "at %s(%s:%d) 没有配置环境变量DB", __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    g_db_user = getenv("DB_USER");
    if(cstr_empty(g_db_user)) {
        dcs_log(0, 0, "at %s(%s:%d) 没有配置环境变量DB_USER", __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    g_db_pwd = getenv("DB_PWD");
    if(cstr_empty(g_db_pwd)) {
        dcs_log(0, 0, "at %s(%s:%d) 没有配置环境变量DB_PWD", __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    g_db_pwd_mode = getenv("DB_PWD_MODE");
    if(cstr_empty(g_db_pwd_mode)) {
        g_db_pwd_mode = "0";
    }

    if(oci_initialize(sql_error_handler, OCI_ENV_DEFAULT) == FALSE) {
        dcs_log(0, 0, "oci_initialize失败");
        goto error;
    }

    bzero(db_pwd, sizeof(db_pwd));
    if(strcmp(g_db_pwd_mode, "1") == 0) {
        decrypt_db_pwd(g_db_pwd, db_pwd, sizeof(db_pwd));
    } else {
        cstr_copy(db_pwd, g_db_pwd, sizeof(db_pwd));
    }

    if((g_db_con = oci_connection_new(g_db, g_db_user, db_pwd)) == NULL) {
        dcs_log(0, 0, "oci_connection_new失败");
        goto error;
    }

    if(sql_init(g_db_con) != 0) {
        dcs_log(0, 0, "at %s(%s:%d) SQL库初始化失败", __FUNCTION__, __FILE__, __LINE__);
        goto error;
    }

    if(load_fun_config(g_db_con) != 0) {
        dcs_log(0, 0, "at %s(%s:%d) 加载功能配置失败", __FUNCTION__, __FILE__, __LINE__);
        goto error;
    }

    if(load_data_rule(g_db_con) != 0) {
        dcs_log(0, 0, "at %s(%s:%d) 加载数据权限规则失败", __FUNCTION__, __FILE__, __LINE__);
        goto error;
    }

    return 1;

error:

    sql_destroy();
    oci_connection_free(g_db_con);
    oci_cleanup();

    return -1;
}

void app_exit(server *srv) {

    sql_destroy();
    oci_connection_free(g_db_con);
    oci_cleanup();

    return;
}

