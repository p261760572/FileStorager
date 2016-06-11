#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <assert.h>


#define MAX_PARA_BUF_SIZE 1024*16
#define MAX_PARA_SIZE 128
#define NEWLAND_PARA_VER_SIZE 32

struct string_s {
    char *p;
    int len;
};

typedef struct string_s string_t;


struct pair_s {
    string_t k;
    string_t v;
};

typedef struct pair_s pair_t;

//新大陆
struct newland_para_s {
    char buf[MAX_PARA_BUF_SIZE];
    int buf_len;
    pair_t para[MAX_PARA_SIZE];
    int para_len;
    string_t ver;
};

typedef struct newland_para_s newland_para_t;


//百富
struct pax_para_s {
    char buf[MAX_PARA_BUF_SIZE];
    int buf_len;
    pair_t para[MAX_PARA_SIZE];
    int para_len;
};

typedef struct pax_para_s pax_para_t;


//新国都

int string_cmp(const string_t *str1, const char *str2) {
    size_t n2 = strlen(str2), n1 = str1->len;
    int r = memcmp(str1->p, str2, (n1 < n2) ? n1 : n2);
    if(r == 0) {
        return n1 - n2;
    }
    return r;
}



unsigned int to_uint16(char *s) {
    unsigned char *p = (unsigned char *)s;
    return p[0] + (p[1] << 8);
}

void parse_newland_para(char *buf, int buf_len, newland_para_t *para) {
    assert(buf_len <= MAX_PARA_BUF_SIZE);

    //para->buf = buf;
    memcpy(para->buf, buf, buf_len);
    para->buf_len = buf_len;

    int offset = 0;

    para->ver.p = para->buf + offset;
    para->ver.len = 32;
    offset += para->ver.len;

    para->para_len = to_uint16(para->buf+offset);
    offset += 2;

    if(para->para_len > MAX_PARA_SIZE) {
        para->para_len = MAX_PARA_SIZE;
    }

    int i;
    for(i = 0; i < para->para_len; i++) {
        para->para[i].k.p =  para->buf + to_uint16(para->buf+offset);
        para->para[i].k.len = to_uint16(para->buf+offset+2);
        offset += 4;

        para->para[i].v.p =  para->buf + to_uint16(para->buf+offset);
        para->para[i].v.len = to_uint16(para->buf+offset+2);
        offset += 4;
    }
}

int update_newland_para(newland_para_t *para, char *key, char *value) {
    int i;
    for(i = 0; i < para->para_len; i++) {
        if(string_cmp(&para->para[i].k, key) == 0) {
            break;
        }
    }

    if(i == para->para_len) {
        if(para->para_len >= MAX_PARA_SIZE) {
            return -1;
        } else {
            para->para_len++;
        }
    }

    size_t key_len = strlen(key), value_len = strlen(value);
    if(para->buf_len + key_len + value_len > MAX_PARA_BUF_SIZE) {
        return -1;
    } else {
        para->para[i].k.p = para->buf+para->buf_len;
        para->para[i].k.len = key_len;
        para->buf_len += key_len;
        memcpy(para->para[i].k.p, key, key_len);


        para->para[i].v.p = para->buf+para->buf_len;
        para->para[i].v.len = value_len;
        para->buf_len += value_len;
        memcpy(para->para[i].v.p , value, value_len);
    }


    return 0;
}


void parse_pax_para(char *buf, int buf_len, pax_para_t *para) {
    assert(buf_len <= MAX_PARA_BUF_SIZE);

    //para->buf = buf;
    memcpy(para->buf, buf, buf_len);
    para->buf_len = buf_len;

    int offset = 0, i;
    while(offset < para->buf_len) {
        i = para->para_len;
        para->para[i].k.p =  para->buf + offset;
        para->para[i].k.len = 8;
        offset += 8;

        para->para[i].v.p =  para->buf + offset;
        para->para[i].v.len = 120;
        offset += 120;

        para->para_len++;

        if(para->para_len >= MAX_PARA_SIZE) {
            break;
        }
    }
}

int update_pax_para(pax_para_t *para, char *key, char *value) {
    int i;
    for(i = 0; i < para->para_len; i++) {
        if(strncmp(para->para[i].k.p, key, 8) == 0) {
            break;
        }
    }

    size_t key_len = strlen(key), value_len = strlen(value);

    if(i == para->para_len) {
        if(para->para_len >= MAX_PARA_SIZE) {
            return -1;
        } else if(para->buf_len + 128 > MAX_PARA_BUF_SIZE) {
            return -1;
        } else {
            para->para_len++;

            para->para[i].k.p = para->buf+para->buf_len;
            para->para[i].k.len = 8;
            para->buf_len += 8;
			bzero(para->para[i].k.p, para->para[i].k.len); 
            memcpy(para->para[i].k.p, key, key_len < 8 ? key_len : 8);


            para->para[i].v.p = para->buf+para->buf_len;
            para->para[i].v.len = 120;
            para->buf_len += 120;
			bzero(para->para[i].v.p, para->para[i].v.len); 
            memcpy(para->para[i].v.p , value, value_len < 120 ? value_len : 120);
        }
    } else {
    	bzero(para->para[i].v.p, para->para[i].v.len); 
        memcpy(para->para[i].v.p , value, value_len < 120 ? value_len : 120);
    }

    return 0;
}



void print_newland_para(newland_para_t *newland) {
    int i;
    fprintf(stderr, "ver=[%.*s]\n", newland->ver.len, newland->ver.p);
    for(i = 0; i < newland->para_len; i++) {
        //fprintf(stderr, "[%d]=[%d][%d]\n", i, newland.newland[i].k.len, newland.newland[i].v.len);
        fprintf(stderr, "[%d]=[%.*s][%.*s]\n", i, newland->para[i].k.len, newland->para[i].k.p, newland->para[i].v.len, newland->para[i].v.p);
    }
}

void print_pax_para(pax_para_t *pax) {
    int i;
    for(i = 0; i < pax->para_len; i++) {
        fprintf(stderr, "[%d]=[%.*s][%.*s]\n", i, pax->para[i].k.len, pax->para[i].k.p, pax->para[i].v.len, pax->para[i].v.p);
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
    bzero(&newland, sizeof(newland));
    parse_newland_para(buf, n, &newland);

#if 0
    print_newland_para(&newland);

    update_newland_para(&newland, "01000005", "TTTTTTTT");
    update_newland_para(&newland, "01000001", "MMMMMMMMMMMMMMM");

    print_newland_para(&newland);
#endif

    fclose(fp);



    fp = fopen("pax", "r");

    //fprintf(stderr, "%p", fp);

    n = fread(buf, 1, sizeof(buf), fp);

    fprintf(stderr, "%zd %s\n", n, strerror(ferror(fp)));


    pax_para_t pax;
    bzero(&pax, sizeof(pax));
    parse_pax_para(buf, n, &pax);

    print_pax_para(&pax);

	
    update_pax_para(&pax, "终端号", "TTTTTTTT");

    update_pax_para(&pax, "商户号", "MMMMMMMMMMMMMMM");

    print_pax_para(&pax);


    fclose(fp);


    return 0;
}

