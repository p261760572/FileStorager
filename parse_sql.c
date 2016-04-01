#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "cdefs.h"
#include "cstr.h"
#include "parse_sql.h"

#define DEFAULT_BUFFER_SIZE 1024
#define VALUE_DELIMIT_CHAR ','


/*
*Return:
*   成功返回写入的字节数，失败返回小于0或大于等于buf_size
*/
int create_psql_like(void *head, const char *table_name, const char *column_name, const char *value, char *buf, int buf_size)
{
    if(head == NULL || column_name == NULL ||
       value == NULL || buf == NULL)
    {
        return -1;
    }
    int buf_offset = 0;
    if(table_name != NULL && strlen(table_name) > 0)
    {
        buf_offset = snprintf(buf,buf_size,"%s.%s like '%%%s%%'",table_name,column_name,value);
    }
    else
    {
        buf_offset = snprintf(buf,buf_size,"%s like '%%%s%%'",column_name,value);
    }
    return buf_offset;
}

/*
*Return:
*   成功返回写入的字节数，失败返回小于0或大于等于buf_size
*/
int create_psql_like2(void *head, const char *table_name, const char *column_name, const char *value, char *buf, int buf_size)
{
    if(head == NULL || column_name == NULL ||
       value == NULL || buf == NULL)
    {
        return -1;
    }
    int buf_offset = 0;
    if(table_name != NULL && strlen(table_name) > 0)
    {
        buf_offset = snprintf(buf,buf_size,"%s.%s like '%s%%'",table_name,column_name,value);
    }
    else
    {
        buf_offset = snprintf(buf,buf_size,"%s like '%s%%'",column_name,value);
    }
    return buf_offset;
}

/*
*Return:
*   成功返回写入的字节数，失败返回小于0或大于等于buf_size
*/
int create_psql_between(void *head, const char *table_name, const char *column_name, const char *value, char *buf, int buf_size)
{
    if(head == NULL || column_name == NULL ||
       value == NULL || buf == NULL)
    {
        return -1;
    }

    int buf_offset = 0;

    char *p = strchr(value,',');
    if(p == NULL)
    {
        if(table_name != NULL && strlen(table_name) > 0)
        {
            buf_offset = snprintf(buf,buf_size,"%s.%s = '%s'",table_name,column_name,value);
        }
        else
        {
            buf_offset = snprintf(buf,buf_size,"%s = '%s'",column_name,value);
        }
    }
    else
    {
        *p = '\0';
        if(table_name != NULL && strlen(table_name) > 0)
        {
            buf_offset = snprintf(buf,buf_size,"%s.%s between '%s' and '%s'",table_name,column_name,value,p+1);
        }
        else
        {
            buf_offset = snprintf(buf,buf_size,"%s between '%s' and '%s'",column_name,value,p+1);
        }
        *p = ',';
    }

    return buf_offset;
}

/*
*@fucntion
*   会用and做连接
*@return
*   成功返回写入的字节数，失败返回小于0或大于等于buf_size
*/
int create_psql_in_or_not_in(void *head, const char *table_name, const char *column_name, const char *operate, const char *value, char *buf, int buf_size)
{
    if(head == NULL || column_name == NULL || value == NULL || buf == NULL)
    {
        return -1;
    }

    int buf_offset = 0;
    char column_value[DEFAULT_BUFFER_SIZE];

    const char *p;
    const char *pre;
    const char *t;

    if(table_name != NULL && strlen(table_name) > 0)
    {
        buf_offset = snprintf(buf, buf_size, "%s.%s %s (", table_name, column_name, operate);
    }
    else
    {
        buf_offset = snprintf(buf, buf_size, "%s %s (", column_name, operate);
    }

	if(strcmp(value, "{CurrentOriginal}") == 0)
	{
		#if 0
		if(head->user_data)
		{
			value = json_object_get_string(json_object_object_get(head->user_data, column_name));
		}
		#endif
		
		if(value == NULL)
		{
			value = "{CurrentOriginal}"; //配置有问题
		}
	}

    pre = value;
    while((p = strchr(pre,VALUE_DELIMIT_CHAR)) != NULL)
    {
        memset(column_value, 0, sizeof(column_value));
        cstr_copy(column_value,pre,p-pre+1);

		if((t = get_current_value(head, column_value)) != NULL)
		{
			strcpy(column_value, t);
		}

        buf_offset += snprintf(buf+buf_offset, buf_size-buf_offset, "'%s',", column_value);

        pre = p + 1;
    }

    p = strchr(pre,'\0');

    memset(column_value, 0, sizeof(column_value));
    cstr_copy(column_value,pre,p-pre+1);

	if((t = get_current_value(head, column_value)) != NULL)
	{
		strcpy(column_value, t);
	}

    buf_offset += snprintf(buf+buf_offset, buf_size-buf_offset, "'%s')", column_value);

    return buf_offset;
}


/*
*@fucntion
*   会用and做连接
*@return
*   成功返回写入的字节数，失败返回小于0或大于等于buf_size
*/
int create_psql_in(void *head, const char *table_name, const char *column_name,const char *value, char *buf, int buf_size)
{
    return create_psql_in_or_not_in(head, table_name, column_name, "in", value, buf, buf_size);
}

#if 0
/*
*Return:
*   成功返回写入的字节数，失败返回小于0或大于等于buf_size
*/
int create_psql_in2(const char *userid, const char *table_name, const char *column_name, const char *value, char *buf, int buf_size)
{
    if(userid == NULL || column_name == NULL || value == NULL || buf == NULL)
    {
        return -1;
    }

    int buf_offset = 0;
    char column_value[DEFAULT_BUFFER_SIZE];

    const char *p;
    const char *pre;

    if(table_name != NULL && strlen(table_name) > 0)
    {
        buf_offset = snprintf(buf, buf_size, " %s.%s in (", table_name, column_name);
    }
    else
    {
        buf_offset = snprintf(buf, buf_size, " %s in (", column_name);
    }

    pre = value;
    while((p = strchr(pre,VALUE_DELIMIT_CHAR)) != NULL)
    {
        memset(column_value, 0, sizeof(column_value));
        strcpy_s(column_value,pre,p-pre+1);

        if(strcmp(column_value,"{CurrentUserID}") == 0)
        {
            strcpy(column_value,userid);
        }
        buf_offset += snprintf(buf+buf_offset, buf_size-buf_offset, "'%s',", column_value);

        pre = p + 1;
    }

    p = strchr(pre,'\0');

    memset(column_value, 0, sizeof(column_value));
    strcpy_s(column_value,pre,p-pre+1);

    if(strcmp(column_value,"{CurrentUserID}") == 0)
    {
        strcpy(column_value,userid);
    }
    buf_offset += snprintf(buf+buf_offset, buf_size-buf_offset, "'%s')", column_value);

    return buf_offset;
}
#endif


/*
*Return:
*   成功返回写入的字节数，失败返回小于0或大于等于buf_size
*/
int create_psql_by_operate(void *head, const char *table_name, const char *column_name, const char *operate, const char *value, char *buf, int buf_size)
{
    if(head == NULL || column_name == NULL || operate == NULL
       || value == NULL || buf == NULL)
    {
        return -1;
    }

    int where_offset = 0;
    if(strcmp(operate,"like") == 0)
    {
        where_offset = create_psql_like(head, table_name, column_name, value, buf, buf_size);
    }
    else if(strcmp(operate,"like2") == 0)
    {
        where_offset = create_psql_like2(head, table_name, column_name, value, buf, buf_size);
    }
    else if(strcmp(operate,"between") == 0)
    {
        where_offset = create_psql_between(head, table_name, column_name, value, buf, buf_size);
    }
    else if(strcmp(operate,"in") == 0 || strcmp(operate,"not in") == 0)
    {
        where_offset = create_psql_in_or_not_in(head, table_name, column_name, operate, value, buf, buf_size);
    }
    else
    {
        const char *t = NULL;
        if(strcmp(value, "{CurrentOriginal}") == 0)
        {
			#if 0
            if(head->user_data)
            {
                t = json_object_get_string(json_object_object_get(head->user_data, column_name));
            }
			#endif
        }
        else
        {
            t = get_current_value(head, value);
        }

        if(t == NULL)
            t = value;


        if(table_name != NULL && strlen(table_name) > 0)
        {
            where_offset = snprintf(buf+where_offset,buf_size-where_offset,"%s.%s %s '%s'", table_name, column_name, operate, t);
        }
        else
        {
            where_offset = snprintf(buf+where_offset,buf_size-where_offset,"%s %s '%s'", column_name, operate, t);
        }
    }
    return where_offset;
}


