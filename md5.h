#ifndef _md5_h_
#define _md5_h_

#ifdef __cplusplus
extern "C" {
#endif
// Return stringified MD5 hash for list of strings. Buffer must be 33 bytes.
void md5(char buf[33], ...);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //_md5_h_
