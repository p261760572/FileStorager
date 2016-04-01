#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#include <iconv.h>

#include "cdefs.h"
#include "cbuf.h"
#include "ciconv.h"
#include "json.h"


#define JSON_EXT_FILE_BUF_SIZE 4096
#define JSON_EXT_MAX_FILE_SIZE 1024*1024

json_object *json_util_object_get(json_object *obj, const char *key) {
    struct json_object *result = NULL;
    json_object_object_get_ex(obj, key, &result);
    return result;
}


const char *json_util_object_get_string(json_object* obj, const char *key) {
    json_object *result = json_util_object_get(obj, key);
    return json_object_get_string(result);
}

int json_util_object_get_int(json_object* obj, const char *key) {
    json_object *result = json_util_object_get(obj, key);
    return json_object_get_int(result);
}


json_object* json_util_object_from_file(const char *filename, const char *fromcode, const char *tocode)
{
    cbuf_t buf;
    json_object *obj = NULL;
    char buf2[JSON_EXT_FILE_BUF_SIZE];
    int fd, ret;

    if((fd = open(filename, O_RDONLY)) < 0)
    {
        c_error("error open file %s: %s", filename, strerror(errno));
        return NULL;
    }

    if(cbuf_init(&buf, JSON_EXT_FILE_BUF_SIZE, JSON_EXT_MAX_FILE_SIZE) != 0)
    {
        c_error("cbuf_init failed");
        close(fd);
        return NULL;
    }

    while((ret = read(fd, buf2, JSON_EXT_FILE_BUF_SIZE)) > 0)
    {
        cbuf_append(&buf, buf2, ret);
    }
    close(fd);

    if(ret < 0)
    {
        c_error("error read file %s: %s", filename, strerror(errno));
        cbuf_destroy(&buf);
        return NULL;
    }

    //±àÂë×ª»»
    char *conv_buf = calloc(2*cbuf_len(&buf), 1);
    if(conv_buf == NULL)
    {
        c_error("malloc failed");
    }
    else if(code_convert(fromcode, tocode, cbuf_str(&buf), cbuf_len(&buf), conv_buf, 2*cbuf_len(&buf)) < 0)
    {
        c_error("code_convert failed");
    }
    else
    {
        obj = json_tokener_parse(conv_buf);
    }
    free(conv_buf);

    cbuf_destroy(&buf);

    return obj;
}

int json_util_object_to_file(const char *filename, struct json_object *obj, const char *fromcode, const char *tocode)
{
    int rc = 0;
    const char *json_str;
    int fd, ret;
    unsigned int wpos, wsize;

    if(obj == NULL)
    {
        c_error("object is null");
        return -1;
    }

    if((fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0644)) < 0)
    {
        c_error("error opening file %s: %s", filename, strerror(errno));
        return -1;
    }

    if((json_str = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN)) == NULL)
    {
        close(fd);
        return -1;
    }

    size_t len = strlen(json_str);

    //±àÂë×ª»»
    char *conv_buf = malloc(2*len);
    int conv_size = 0;
    if(conv_buf == NULL)
    {
        c_error("malloc failed");
        rc = -1;
    }
    else if((conv_size=code_convert(fromcode, tocode, (char *)json_str, len, conv_buf, 2*len)) < 0)
    {
        c_error("code_convert failed");
        rc = -1;
    }
    else
    {
        wsize = conv_size;
        wpos = 0;
        while(wpos < wsize)
        {
            if((ret = write(fd, conv_buf + wpos, wsize-wpos)) < 0)
            {
                c_error("error writing file %s: %s", filename, strerror(errno));
                rc = -1;
                break;
            }

            wpos += (unsigned int)ret;
        }
    }
    free(conv_buf);

    close(fd);

    return rc;
}
