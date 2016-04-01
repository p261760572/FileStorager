
#ifndef __cstr_h
#define __cstr_h


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern char *cstr_ltrim(char *str);
extern char *cstr_rtrim(char *str);
extern int cstr_split(char *str, char *delim, char **array, int array_size);
extern char *cstr_substring(char *str, int start, int end);
extern char *cstr_substr(char *str, int start, int end);
extern char *cstr_trim(char *str);
extern char *cstr_copy(char *dest, const char *src, size_t n);
extern int cstr_empty(const char *str);
extern char *cstr_lower(char *str);
extern char *cstr_upper(char *str);
extern const char *cstr_str(const char *str, const char *substr, size_t n);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __cstr_h */
