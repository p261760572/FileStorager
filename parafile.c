#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>

#include "cdefs.h"
#include "cstr.h"
#include "parafile.h"

#include "ibdcs.h"


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


static unsigned long to_uint32(char *s) {
    unsigned char *p = (unsigned char *)s;
    return p[0] + (p[1] << 8) + (p[2] << 16) + (p[3] << 24);
}


static void uint16_to_bytes(unsigned long n, char *s) {
    s[0] = n&0x0ff;
    s[1] = (n>>8)&0x0ff;
}


static void uint32_to_bytes(unsigned long n, char *s) {
    s[0] = n&0x0ff;
    s[1] = (n>>8)&0x0ff;
    s[2] = (n>>16)&0x0ff;
    s[3] = (n>>24)&0x0ff;
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


int xgd_para_init(xgd_para_t *para) {
    bzero(para, sizeof(*para));
    return 0;
}


void xgd_para_destroy(xgd_para_t *para) {
    int i;
    for(i = 0; i < para->len; i++) {
        free(para->options[i].key);
        free(para->options[i].value);
    }

    bzero(para, sizeof(*para));
}


int parse_xgd_para(char *buf, xgd_para_t *para) {

    char *line[MAX_PAX_OPTIONS_SIZE+1], *p;
    int n, i, num;
    char key[1024], value[1024], value_type[100], value_min[100], value_max[100];

    n = cstr_split(buf, "\r\n", line, ARRAY_SIZE(line));
    if(n > MAX_PAX_OPTIONS_SIZE) {
        return -1;
    }

    para->len = 0;
    for(i = 0; i < n; i++) {
        p = cstr_trim(line[i]);
        if(!cstr_empty(p)) {
            bzero(key, sizeof(key));
            bzero(value, sizeof(value));
            bzero(value_type, sizeof(value_type));
            bzero(value_min, sizeof(value_min));
            bzero(value_max, sizeof(value_max));

            num = sscanf(p, "%[^,],%[^,],%[^,],%[^,],%[^,]", key, value_type, value_min, value_max, value);

            if(num != 4 && num != 5) {
                xgd_para_destroy(para);
                dcs_log(0, 0, "at %s(%s:%d) %d[%s]",__FUNCTION__,__FILE__,__LINE__,num, p);
                return -1;
            } else {
                para->options[para->len].key = strdup(key);
                para->options[para->len].value_type = atoi(value_type);
                para->options[para->len].value_min = atoi(value_min);
                para->options[para->len].value_max = atoi(value_max);
                para->options[para->len].value = strdup(value);
                para->len ++;
            }
        }
    }

    return 0;
}


int update_xgd_para(xgd_para_t *para, const char *key, int value_type, int value_min, int value_max, const char *value) {
    int i;
    for(i = 0; i < para->len; i++) {
        if(strcmp(para->options[i].key, key) == 0) {
            break;
        }
    }

    if(i == para->len) {
        if(para->len >= MAX_PAX_OPTIONS_SIZE) {
            return -1;
        }
        para->len++;
        para->options[i].key = strdup(key);
    }

    free(para->options[i].value);
    para->options[i].value_type = value_type;
    para->options[i].value_min = value_min;
    para->options[i].value_max = value_max;
    para->options[i].value = strdup(value);

    return 0;
}


void xgd_para_to_file(xgd_para_t *para, FILE *fp) {
    int i;
    //选项内容
    for(i = 0; i < para->len; i++) {
        fprintf(fp, "%s,%d,%d,%d,%s\r\n", para->options[i].key, para->options[i].value_type,
                para->options[i].value_min, para->options[i].value_max, para->options[i].value);
    }
}

int landi_para_init(landi_para_t *para) {
    bzero(para, sizeof(*para));
    return 0;
}

void landi_para_destroy(landi_para_t *para) {
    int i;
    for(i = 0; i < para->len; i++) {
        free(para->options[i].key.p);
        free(para->options[i].value.p);
    }
}

int parse_landi_para(char *buf, int buf_len, landi_para_t *para) {
    int offset = 0, i, key_offset, value_offset;

    if(buf_len < 128+2) {
        return -1;
    }

    memcpy(para->head.verify, buf+offset, sizeof(para->head.verify));
    offset += sizeof(para->head.verify);

    memcpy(para->head.name, buf+offset, sizeof(para->head.name));
    offset += sizeof(para->head.name);

    memcpy(para->head.type, buf+offset, sizeof(para->head.type));
    offset += sizeof(para->head.type);

    memcpy(para->head.version, buf+offset, sizeof(para->head.version));
    offset += sizeof(para->head.version);

    memcpy(para->head.display, buf+offset, sizeof(para->head.display));
    offset += sizeof(para->head.display);

    memcpy(para->head.area, buf+offset, sizeof(para->head.area));
    offset += sizeof(para->head.area);

    memcpy(para->head.time, buf+offset, sizeof(para->head.time));
    offset += sizeof(para->head.time);

    para->head.checksum = to_uint32(buf+offset);
    offset += 4;

    para->head.len = to_uint32(buf+offset);
    offset += 4;

    memcpy(para->head.reserved, buf+offset, sizeof(para->head.reserved));
    offset += sizeof(para->head.reserved);

    para->head.signFilelen = to_uint16(buf+offset);
    offset += 2;

    para->head.extlen = to_uint16(buf+offset);
    offset += 2;

    para->head.structver = buf[offset];
    offset += 1;

    para->head.endflag = buf[offset];
    offset += 1;

    //end head

    para->len = to_uint16(buf+offset);
    offset += 2;

    if(para->len > MAX_LANDI_OPTIONS_SIZE) {
        landi_para_destroy(para);
        return -1;
    }

    if(offset +  para->len * 8 > buf_len) {
        landi_para_destroy(para);
        return -1;
    }

    for(i = 0; i < para->len; i++) {
        key_offset = to_uint16(buf+offset);
        para->options[i].key.len = to_uint16(buf+offset+2);

        value_offset = to_uint16(buf+offset+4);
        para->options[i].value.len = to_uint16(buf+offset+6);

        if(key_offset + para->options[i].key.len > buf_len ||
           value_offset + para->options[i].value.len > buf_len) {
            landi_para_destroy(para);
            return -1;
        }

        para->options[i].key.p = memdup(buf + key_offset, para->options[i].key.len);
        para->options[i].value.p = memdup(buf + value_offset, para->options[i].value.len);
        offset += 8;
    }

    return 0;
}

int update_landi_para(landi_para_t *para, const char *key, const char *value) {
    int i;
    for(i = 0; i < para->len; i++) {
        if(para_str_cmp(&para->options[i].key, key) == 0) {
            break;
        }
    }

    if(i == para->len) {
        if(para->len >= MAX_LANDI_OPTIONS_SIZE) {
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

void landi_para_to_file(landi_para_t *para, FILE *fp) {
    int offset = 0, i;
    char buf[8];

    fwrite(para->head.verify, 1, sizeof(para->head.verify), fp);
    fwrite(para->head.name, 1, sizeof(para->head.name), fp);
    fwrite(para->head.type, 1, sizeof(para->head.type), fp);
    fwrite(para->head.version, 1, sizeof(para->head.version), fp);
    fwrite(para->head.display, 1, sizeof(para->head.display), fp);
    fwrite(para->head.area, 1, sizeof(para->head.area), fp);
    fwrite(para->head.time, 1, sizeof(para->head.time), fp);

    uint32_to_bytes(para->head.checksum, buf);
    fwrite(buf, 1, 4, fp);

    uint32_to_bytes(para->head.len, buf);
    fwrite(buf, 1, 4, fp);

    fwrite(para->head.reserved, 1, sizeof(para->head.reserved), fp);

    uint16_to_bytes(para->head.signFilelen, buf);
    fwrite(buf, 1, 2, fp);

    uint16_to_bytes(para->head.extlen, buf);
    fwrite(buf, 1, 2, fp);

    fwrite(&para->head.structver, 1, sizeof(para->head.structver), fp);
    fwrite(&para->head.endflag, 1, sizeof(para->head.endflag), fp);

    //跳过头
    fseek(fp, 128, SEEK_SET);
    offset += 128;

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



#if 0

void print_xgd_para(xgd_para_t *para) {
    int i;
    //选项内容
    dcs_log(0,0, "xjb3 %d\n", para->len);
    for(i = 0; i < para->len; i++) {
        dcs_log(0, 0, "%s,%d,%d,%d,%s\n", para->options[i].key, para->options[i].value_type,
                para->options[i].value_min, para->options[i].value_max, para->options[i].value);
    }
}


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

