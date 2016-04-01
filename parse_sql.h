#ifndef KYWEB_PARSE_SQL_H
#define KYWEB_PARSE_SQL_H

#include "cdefs.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


int create_psql_in(void *head, const char *table_name, const char *column_name, const char *value, char *buf, int buf_size);

int create_psql_in2(void *head, const char *table_name, const char *column_name, const char *value, char *buf, int buf_size);

int create_psql_by_operate(void *head, const char *table_name, const char *column_name, const char *operate, const char *value, char *buf, int buf_size);

int create_psql_between(void *head, const char *table_name, const char *column_name, const char *value, char *buf, int buf_size);

int create_psql_like(void *head, const char *table_name, const char *column_name, const char *value, char *buf, int buf_size);

int create_psql_like2(void *head, const char *table_name, const char *column_name, const char *value, char *buf, int buf_size);

char *get_current_value(void *head, const char *name);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // KYWEB_PARSE_SQL_H
