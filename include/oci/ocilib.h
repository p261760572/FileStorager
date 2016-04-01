#ifndef __ocilib_h
#define __ocilib_h

#include <oratypes.h>
#include <ocidfn.h>
#include <oci.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// boolean
#undef TRUE
#define TRUE 1

#undef FALSE
#define FALSE 0

#undef boolean
#define boolean int

#define OCI_SIZE_BUFFER                     512
#define OCI_SIZE_ROWID						23	

// C Data Type mapping
#define OCI_CDT_NUMERIC                     1
#define OCI_CDT_DATETIME                    2
#define OCI_CDT_TIMESTAMP                   3
#define OCI_CDT_STRING                      4
#define OCI_CDT_LOB                         5


// Statement Types mapping
#define  OCI_ST_UNKNOWN 0 
#define  OCI_ST_SELECT  1 
#define  OCI_ST_UPDATE  2 
#define  OCI_ST_DELETE  3 
#define  OCI_ST_INSERT  4 
#define  OCI_ST_CREATE  5 
#define  OCI_ST_DROP    6 
#define  OCI_ST_ALTER   7 
#define  OCI_ST_BEGIN   8 
#define  OCI_ST_DECLARE 9 
#define  OCI_ST_CALL    10


#define OCI_STRING_FORMAT_DATE ("YYYY-MM-DD HH24:MI:SS")
#define OCI_STRING_FORMAT_TIMESTAMP ("YYYY-MM-DD HH24:MI:SS.FF2")
#define OCI_STRING_FORMAT_NUM \
    ("FM99999999999999999999999999999999999990.999999999999999999999999")


#define OCI_ENV_DEFAULT                     0
#define OCI_ENV_THREADED                    1


typedef struct oci_thread_key_s oci_thread_key_t;

typedef struct oci_error_s oci_error_t;

typedef struct oci_connection_s oci_connection_t;

typedef struct oci_statement_s oci_statement_t;

typedef struct oci_resultset_s oci_resultset_t;

typedef struct oci_define_s oci_define_t;

typedef struct oci_date_s oci_date_t;

typedef void (*oci_error_handler)(oci_error_t *err);


extern boolean oci_initialize(oci_error_handler err_handler, unsigned int mode);
extern boolean oci_cleanup();
extern boolean oci_commit(oci_connection_t *con);
extern boolean oci_rollback(oci_connection_t *con);
extern oci_connection_t * oci_connection_new(const char *db, const char *user, const char *pwd);
extern boolean oci_connection_free(oci_connection_t *con);
extern oci_statement_t * oci_statement_new(oci_connection_t *con);
extern boolean oci_statement_free(oci_statement_t *stmt);
extern boolean oci_prepare(oci_statement_t *stmt, const char *sql);

extern int oci_get_bind_count(oci_statement_t * stmt);
extern boolean oci_bind_double(oci_statement_t *stmt, const char *name, double *data);
extern boolean oci_bind_int(oci_statement_t *stmt, const char *name, int *data);
extern boolean oci_bind_string(oci_statement_t *stmt, const char *name, char *data);

extern boolean oci_bind_double_by_pos(oci_statement_t *stmt, unsigned int position, double *data);
extern boolean oci_bind_int_by_pos(oci_statement_t *stmt, unsigned int position, int *data);
extern boolean oci_bind_string_by_pos(oci_statement_t *stmt, unsigned int position, char *data);


extern boolean oci_execute(oci_statement_t *stmt);
extern boolean oci_execute_stmt(oci_statement_t *stmt, const char *sql);
extern unsigned int oci_get_stmt_type(oci_statement_t *stmt);
extern unsigned int oci_get_row_count(oci_statement_t *stmt);
extern oci_resultset_t *oci_get_resultset(oci_statement_t *stmt);

extern boolean oci_fetch_next(oci_resultset_t *rs);
extern unsigned int oci_get_column_count(oci_resultset_t *rs);
extern char *oci_get_column_name(oci_resultset_t * rs, unsigned int index);
extern unsigned int oci_get_column_type(oci_resultset_t * rs, unsigned int index);
extern boolean oci_is_null(oci_resultset_t *rs, unsigned int index);
extern oci_date_t *oci_get_date(oci_resultset_t *rs, unsigned int index);
extern double oci_get_double(oci_resultset_t *rs, unsigned int index);
extern int oci_get_int(oci_resultset_t *rs, unsigned int index);
extern const char *oci_get_string(oci_resultset_t *rs, unsigned int index);

extern oci_thread_key_t *oci_thread_key_new();
extern boolean oci_thread_key_free(oci_thread_key_t *key);
extern boolean oci_thread_key_get(oci_thread_key_t* key, void **value);
extern boolean oci_thread_key_set(oci_thread_key_t* key, void *value);

extern oci_error_t *oci_get_last_error();
extern void oci_set_last_error(int errcode);
extern char *oci_get_error_msg(oci_error_t *err);
extern int oci_get_error_code(oci_error_t *err);
extern boolean oci_get_error_warning(oci_error_t *err);
extern oci_statement_t *oci_get_error_stmt(oci_error_t *err);



#define C_ERROR(...) \
    fprintf(stderr,"at %s(%s:%d)\n",__FUNCTION__,__FILE__,__LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n")

#define C_DEBUG(...) \
    fprintf(stdout, "at %s(%s:%d)\n",__FUNCTION__,__FILE__,__LINE__); \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n")


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __ocilib_h */
