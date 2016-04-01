/**
 *
 *  Created on: 2013/4/5
 *  Author: xjb
 *  Email: beymy.en@gmail.com
 */

#ifndef __cdefs_h
#define __cdefs_h

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef int cbool;

#define CTRUE ((cbool)1)
#define CFALSE ((cbool)0)

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#define ASSERT_PTR(p) assert(p != NULL)
#define CHECK(e, r)     \
    if(e)               \
    {                   \
        return r;       \
    }


#define c_error(...) \
    fprintf(stderr,"error=>at %s(%s:%d)",__FUNCTION__,__FILE__,__LINE__); \
    fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n")

#define c_warn(...) \
    fprintf(stdout, "warn=>at %s(%s:%d)",__FUNCTION__,__FILE__,__LINE__); \
    fprintf(stdout, __VA_ARGS__); \
	fprintf(stdout, "\n")

#define c_debug(...) \
    fprintf(stdout, "debug=>at %s(%s:%d)",__FUNCTION__,__FILE__,__LINE__); \
    fprintf(stdout, __VA_ARGS__); \
	fprintf(stdout, "\n")


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif //__cdefs_h

