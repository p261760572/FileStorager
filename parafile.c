#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>

#include "parafile.h"


static void *memdup(void *src, size_t n) {
    void *dest = malloc(n);
    if(dest != NULL) {
        memcpy(dest, src, n);
    }
    return dest;
}


static int para_str_cmp(const para_str_t *str1, const char *str2) {
    size_t n2 = strlen(str2), n1 = str1->len;
    int r = memcmp(str1->p, str2, (n1 < n2) ? n1 : n2);
    if(r == 0) {
        return n1 - n2;
    }
    return r;
}


static unsigned int to_uint16(char *s) {
    unsigned char *p = (unsigned char *)s;
    return p[0] + (p[1] << 8);
}


int newland_para_init(newland_para_t *para) {
    bzero(para, sizeof(*para));
    return 0;
}

void newland_para_destroy(newland_para_t *para) {
    int i;
    for(i = 0; i < para->len; i++) {
        free(para->options[i].key.p);
        free(para->options[i].value.p);
    }
    free(para->ver.p);
	bzero(para, sizeof(*para));
}

int parse_newland_para(char *buf, int buf_len, newland_para_t *para) {
    int offset = 0, i, key_offset, value_offset;

    if(buf_len < 34) {
        return -1;
    }

    para->ver.len = 32;
    para->ver.p = memdup(buf + offset, para->ver.len);
    offset += para->ver.len;

    para->len = to_uint16(buf+offset);
    offset += 2;

    if(para->len > MAX_NEWLAND_OPTIONS_SIZE) {
		newland_para_destroy(para);
        return -1;
    }

    if(offset +  para->len * 8 > buf_len) {
		newland_para_destroy(para);
        return -1;
    }

    for(i = 0; i < para->len; i++) {
		key_offset = to_uint16(buf+offset);
        para->options[i].key.len = to_uint16(buf+offset+2);
		
		value_offset = to_uint16(buf+offset+4);
		para->options[i].value.len = to_uint16(buf+offset+6);

		if(key_offset + para->options[i].key.len > buf_len ||
			value_offset + para->options[i].value.len > buf_len) {
			newland_para_destroy(para);
			return -1;
		}
		
        para->options[i].key.p = memdup(buf + key_offset, para->options[i].key.len);
        para->options[i].value.p = memdup(buf + value_offset, para->options[i].value.len);
        offset += 8;
    }

    return 0;	
}

int update_newland_para(newland_para_t *para, const char *key, const char *value) {
    int i;
    for(i = 0; i < para->len; i++) {
        if(para_str_cmp(&para->options[i].key, key) == 0) {
            break;
        }
    }

    if(i == para->len) {
        if(para->len >= MAX_NEWLAND_OPTIONS_SIZE) {
            return -1;
        }
        para->len++;

        para->options[i].key.len = strlen(key);
        para->options[i].key.p = memdup((void *)key, para->options[i].key.len);
    }

    if(para->options[i].value.p != NULL) {
        free(para->options[i].value.p);
    }

    para->options[i].value.len = strlen(value);
    para->options[i].value.p = memdup((void *)value, para->options[i].value.len);

    return 0;
}

void newland_para_to_file(newland_para_t *para, FILE *fp) {
    int offset = 0, i;
    char buf[8];

    fwrite(para->ver.p, 1, para->ver.len, fp);
    offset += para->ver.len;

    //选项个数
    buf[0] = para->len&0x0ff;
    buf[1] = (para->len>>8)&0x0ff;
    fwrite(buf, 1, 2, fp);
    offset += 2;

    //选项位置偏移
    offset += (para->len * 8);
    for(i = 0; i < para->len; i++) {

        buf[0] = offset&0x0ff;
        buf[1] = (offset>>8)&0x0ff;
        buf[2] = para->options[i].key.len&0x0ff;
        buf[3] = (para->options[i].key.len>>8)&0x0ff;
        offset += para->options[i].key.len;

        buf[4] = offset&0x0ff;
        buf[5] = (offset>>8)&0x0ff;
        buf[6] = para->options[i].value.len&0x0ff;
        buf[7] = (para->options[i].value.len>>8)&0x0ff;
        offset += para->options[i].value.len;

        fwrite(buf, 1, sizeof(buf), fp);
    }

    //选项内容
    for(i = 0; i < para->len; i++) {
        fwrite(para->options[i].key.p, 1, para->options[i].key.len, fp);
        fwrite(para->options[i].value.p, 1, para->options[i].value.len, fp);
    }
}


int pax_para_init(pax_para_t *para) {
    bzero(para, sizeof(*para));
    return 0;
}

void pax_para_destroy(pax_para_t *para) {
	bzero(para, sizeof(*para));
}


int parse_pax_para(char *buf, int buf_len, pax_para_t *para) {
    int offset = 0;
    while(offset + 128 <= buf_len) {
        memcpy(para->options[para->len].key, buf+offset, 8);
        memcpy(para->options[para->len].value, buf+offset+8, 120);
        para->len++;

        offset += 128;

        if(para->len >= MAX_PAX_OPTIONS_SIZE) {
            break;
        }
    }

    if(offset != buf_len) {
		pax_para_destroy(para);
        return -1;
    }

    return 0;
}


int update_pax_para(pax_para_t *para, const char *key, const char *value) {
    int i;
    for(i = 0; i < para->len; i++) {
        if(strncmp(para->options[i].key, key, 8) == 0) {
            break;
        }
    }

    if(i == para->len) {
        if(para->len >= MAX_PAX_OPTIONS_SIZE) {
            return -1;
        }
        para->len++;
        strncpy(para->options[i].key, key, 8);
    }

    strncpy(para->options[i].value, value, 120);

    return 0;
}


void pax_para_to_file(pax_para_t *para, FILE *fp) {
    int i;
    //选项内容
    for(i = 0; i < para->len; i++) {
        fwrite(para->options[i].key, 1, sizeof(para->options[0].key), fp);
        fwrite(para->options[i].value, 1, sizeof(para->options[0].value), fp);
    }
}

#if 0

void print_newland_para(newland_para_t *newland) {
    int i;
    fprintf(stderr, "ver=[%.*s]\n", newland->ver.len, newland->ver.p);
    for(i = 0; i < newland->len; i++) {
        //fprintf(stderr, "[%d]=[%d][%d]\n", i, newland.newland[i].k.len, newland.newland[i].v.len);
        fprintf(stderr, "[%d]=[%.*s][%.*s]\n", i, newland->options[i].key.len, newland->options[i].key.p, newland->options[i].value.len, newland->options[i].value.p);
    }
}


void print_pax_para(pax_para_t *pax) {
    int i;
    for(i = 0; i < pax->len; i++) {
        fprintf(stderr, "[%d]=[%.*s][%.*s]\n", i, 8, pax->options[i].key, 120, pax->options[i].value);
    }
}


int main(int argc, char *argv[]) {

    char buf[1024*32];
    size_t n;
    FILE *fp;

    fp = fopen("newland", "r");

    //fprintf(stderr, "%p", fp);

    n = fread(buf, 1, sizeof(buf), fp);


    newland_para_t newland;
    newland_para_init(&newland);
    parse_newland_para(buf, n, &newland);

    print_newland_para(&newland);

    update_newland_para(&newland, "01000005", "TTTTTTTT");
    update_newland_para(&newland, "01000001", "MMMMMMMMMMMMMMM");

    print_newland_para(&newland);

    {
        FILE *fw = fopen("newland2", "wb");
        newland_para_to_file(&newland, fw);
        fclose(fw);
    }

    newland_para_destroy(&newland);

    fclose(fp);



    fp = fopen("pax", "r");

    //fprintf(stderr, "%p", fp);

    n = fread(buf, 1, sizeof(buf), fp);

    fprintf(stderr, "%zd %s\n", n, strerror(ferror(fp)));


    pax_para_t pax;
    pax_para_init(&pax);
    parse_pax_para(buf, n, &pax);

    print_pax_para(&pax);

    update_pax_para(&pax, "终端号", "TTTTTTTT");

    update_pax_para(&pax, "商户号", "MMMMMMMMMMMMMMM");

    print_pax_para(&pax);


    {
        FILE *fw = fopen("pax2", "wb");
        pax_para_to_file(&pax, fw);
        fclose(fw);
    }

    pax_para_destroy(&pax);


    fclose(fp);

    return 0;
}
#endif

