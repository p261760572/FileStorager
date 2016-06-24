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


typedef void (*custom_fn)(process_ctx_t *ctx, json_object *request, json_object *response);


struct custom_module {
    char *action;
    custom_fn fn;
};

struct custom_module my_custom_module[] = {
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

