#define MAX_PARA_SIZE 64
#define NEWLAND_PARA_VER_SIZE 32

struct string_s {
	char *p;
	int len;
} string_t;


struct pair_s {
	string_t k;
	string_t v;
} pair_t;


//新大陆
struct newland_para_s {
	char *buf;
	int buf_size;
	pair_t para[MAX_PARA_SIZE];
	int para_len;
	string_t ver;
} newland_para_t;


//百富
struct pax_para_s {
	char *buf;
	int buf_size;
	pair_t para[MAX_PARA_SIZE];
	int para_len;
} pax_para_t;

//新国都

int str2int(char *s) {
	return s[0] + s[0] << 8;  
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



