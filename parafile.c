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
	char ver[NEWLAND_PARA_VER_SIZE];
};


//百富
struct pax_para_s {
	char *buf;
	int buf_size;
	pair_t para[MAX_PARA_SIZE];
	int para_len;
};

//新国都

