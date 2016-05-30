/*
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 * All rights reserved
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 */

#ifndef BASE64_HEADER_INCLUDED
#define	BASE64_HEADER_INCLUDED

const unsigned char Base64ValTab[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const unsigned char Base64IdxTab[128] =
{
	255,255,255,255,  255,255,255,255,  255,255,255,255,  255,255,255,255,
	255,255,255,255,  255,255,255,255,  255,255,255,255,  255,255,255,255,
	255,255,255,255,  255,255,255,255,  255,255,255,62,   255,255,255,63,
	52,53,54,55,      56,57,58,59,      60,61,255,255,    255,255,255,255,
	255,0,1,2,        3,4,5,6,          7,8,9,10,         11,12,13,14,
	15,16,17,18,      19,20,21,22,      23,24,25,255,     255,255,255,255,
	255,26,27,28,     29,30,31,32,      33,34,35,36,      37,38,39,40,
	41,42,43,44,      45,46,47,48,      49,50,51,255,     255,255,255,255
};

#define AVal(x) Base64ValTab[x]
#define BVal(x) Base64IdxTab[x]
#define BYTE unsigned char

extern int EncodeBase64(unsigned char *pInput, char *pOutput, int size);
extern int DecodeBase64(char *pInput, unsigned char *pOutput);
#endif /*MD5_HEADER_INCLUDED */
