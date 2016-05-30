#ifndef _XML_H_
#define _XML_H_  
typedef int (*message_handler)(char *nameBuf, const message_define *priv_def, char *valBuf, int valSize, glob_msg_stru *pub_data_stru); 
typedef struct
{
    char *handlerStr;
    message_handler handler;
}xml_handler_def;                                                              
#endif
