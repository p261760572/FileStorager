#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <errno.h>



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
    char *buf;
    int buf_size;
    pair_t para[MAX_PARA_SIZE];
    int para_len;
    string_t ver;
};

typedef struct newland_para_s newland_para_t;


//百富
struct pax_para_s {
    char *buf;
    int buf_size;
    pair_t para[MAX_PARA_SIZE];
    int para_len;
};

typedef struct pax_para_s pax_para_t;


//新国都
int str2int(char *s) {
    unsigned char *p = (unsigned char *)s;
    return p[0] + (p[1] << 8);
}

void parse_newland_para(char *buf, int buf_len, newland_para_t *para) {
    para->buf = buf;
    para->buf_size = buf_len;

    int offset = 0;

    para->ver.p = para->buf + offset;
    para->ver.len = 32;
    offset += para->ver.len;

    para->para_len = str2int(para->buf+offset);
    offset += 2;

    if(para->para_len > MAX_PARA_SIZE) {
        para->para_len = MAX_PARA_SIZE;
    }

    int i;
    for(i = 0; i < para->para_len; i++) {
        para->para[i].k.p =  para->buf + str2int(para->buf+offset);
        para->para[i].k.len = str2int(para->buf+offset+2);
        offset += 4;

        para->para[i].v.p =  para->buf + str2int(para->buf+offset);
        para->para[i].v.len = str2int(para->buf+offset+2);
        offset += 4;
    }
}

void parse_pax_para(char *buf, int buf_len, pax_para_t *para) {
    para->buf = buf;
    para->buf_size = buf_len;

    int offset = 0, i;
    while(offset < para->buf_size) {
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


int main(int argc, char *argv[]) {

    char buf[1024*32];
    size_t n;
    int i;
    FILE *fp;

    fp = fopen("newland", "r");

    //fprintf(stderr, "%p", fp);

    n = fread(buf, 1, sizeof(buf), fp);


    newland_para_t newland;
    bzero(&newland, sizeof(newland));
    parse_newland_para(buf, n, &newland);

    fprintf(stderr, "ver=[%.*s]\n", newland.ver.len, newland.ver.p);
    for(i = 0; i < newland.para_len; i++) {
        //fprintf(stderr, "[%d]=[%d][%d]\n", i, newland.newland[i].k.len, newland.newland[i].v.len);
        fprintf(stderr, "[%d]=[%.*s][%.*s]\n", i, newland.para[i].k.len, newland.para[i].k.p, newland.para[i].v.len, newland.para[i].v.p);
    }

    fclose(fp);



    fp = fopen("pax", "r");

    //fprintf(stderr, "%p", fp);

    n = fread(buf, 1, sizeof(buf), fp);

    fprintf(stderr, "%zd %s\n", n, strerror(ferror(fp)));


    pax_para_t pax;
    bzero(&pax, sizeof(pax));
    parse_pax_para(buf, n, &pax);

    for(i = 0; i < pax.para_len; i++) {
        fprintf(stderr, "[%d]=[%.*s][%.*s]\n", i, pax.para[i].k.len, pax.para[i].k.p, pax.para[i].v.len, pax.para[i].v.p);
    }

    fclose(fp);


    return 0;
}

