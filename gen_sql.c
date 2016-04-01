#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "cdefs.h"
#include "cstr.h"
#include "cbuf.h"
#include "carray.h"


enum sql_status
{
    tk_illegal = 0,
    tk_other = 1,
    tk_string = 2,
    tk_bind_var = 3
};

/*
*@return ·µ»Øtoken_type
*/
static int get_token(char *s, int l, int idx, int *token_len)
{
    int i = idx;

    if(s[i] == '\'')
    {
        i += 1;
        while(i < l)
        {
            if(s[i] != '\'')
            {
                i += 1;
            }
            else if(strncmp(s+i, "''", 2) == 0)
            {
                i += 2;
            }
            else
            {
                i += 1;
                *token_len = i - idx;
                return tk_string;
            }
        }
        *token_len = i - idx;
        return   tk_illegal;
    }
    else if(s[i] == ':')
    {
        i += 1;
        while(i < l && (isalnum(s[i]) || s[i] == '_'))
        {
            i += 1;
        }
        int ll = i - idx;
        if(ll > 1)
        {
            *token_len = ll;
            return tk_bind_var;
        }
        *token_len = ll;
        return  tk_illegal;
    }
    else
    {
        while(i < l && s[i] != '\'' && s[i] != ':')
        {
            i += 1;
        }
        *token_len = i - idx;
        return tk_other;
    }
}

int gen_sql(char *sql, cbuf_t *sqlbuf, carray_t *bind)
{
	int ret = 0;
    int l = strlen(sql);
    int idx = 0;
	int count = 0;
    while(idx < l)
    {
        int token_len;
        int token_type = get_token(sql, l, idx, &token_len);
        if(token_type == tk_illegal)
        {
			ret = -1;
            goto error;
        }

        if(token_type == tk_bind_var)
        {
            char *value = carray_get(bind, count);
			cbuf_append(sqlbuf, "'", 1);
			if(value)
			{
				cbuf_append(sqlbuf, value, strlen(value));	
			}
			cbuf_append(sqlbuf, "'", 1);
			count ++;
        }
        else
        {
            cbuf_append(sqlbuf, sql+idx, token_len);
        }

        idx = idx + token_len;
    }
error:
    return ret;
}

