/******************************************************************************
  文 件 名   : parafile.h
  版 本 号   : 初稿
  作    者   : xjb
  生成日期   : 2016年6月13日
  功能描述   : parafile.c 的头文件
  函数列表   :
  修改历史   :
  1.日    期   : 2016年6月13日
    作    者   : xjb
    修改内容   : 创建文件

*****************************************************************************/

#ifndef __parafile_h
#define __parafile_h


#ifdef __cplusplus
extern "C"{
#endif /* __cplusplus */


#define MAX_NEWLAND_OPTIONS_SIZE 128
#define MAX_PAX_OPTIONS_SIZE 128
#define MAX_XGD_OPTIONS_SIZE 128


struct para_str_s {
    char *p;
    int len;
};

typedef struct para_str_s para_str_t;


//新大陆
struct newland_option_s {
    para_str_t key;
    para_str_t value;
};

typedef struct newland_option_s newland_option_t;


struct newland_para_s {
    newland_option_t options[MAX_NEWLAND_OPTIONS_SIZE];
    int len;
    para_str_t ver;
};

typedef struct newland_para_s newland_para_t;


//百富
struct pax_option_s {
    char key[8];
    char value[120];
};

typedef struct pax_option_s pax_option_t;

struct pax_para_s {
    pax_option_t options[MAX_PAX_OPTIONS_SIZE];
    int len;
};

typedef struct pax_para_s pax_para_t;

//新国都
struct xgd_option_s {
    char *key;
	int value_type;
	int value_min;
	int value_max;
    char *value;
};

typedef struct xgd_option_s xgd_option_t;

struct xgd_para_s {
    xgd_option_t options[MAX_XGD_OPTIONS_SIZE];
    int len;
};

typedef struct xgd_para_s xgd_para_t;


extern void newland_para_destroy(newland_para_t *para);
extern int newland_para_init(newland_para_t *para);
extern void newland_para_to_file(newland_para_t *para, FILE *fp);
extern int parse_newland_para(char *buf, int buf_len, newland_para_t *para);
extern int parse_pax_para(char *buf, int buf_len, pax_para_t *para);
extern int parse_xgd_para(char *buf, xgd_para_t *para);
extern void pax_para_destroy(pax_para_t *para);
extern int pax_para_init(pax_para_t *para);
extern void pax_para_to_file(pax_para_t *para, FILE *fp);
extern int update_newland_para(newland_para_t *para, const char *key, const char *value);
extern int update_pax_para(pax_para_t *para, const char *key, const char *value);
extern int update_xgd_para(xgd_para_t *para, const char *key, int value_type, int value_min, int value_max, const char *value);
extern void xgd_para_destroy(xgd_para_t *para);
extern int xgd_para_init(xgd_para_t *para);
extern void xgd_para_to_file(xgd_para_t *para, FILE *fp);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __parafile_h */
