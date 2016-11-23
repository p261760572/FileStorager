CC = gcc
CFLAGS = -g -Wall -pthread -I$(ORACLE_HOME)/rdbms/public -Iinclude -Iinclude/cutil -Iinclude/json-c -Iinclude/exp -Iinclude/oci -Iinclude/sql -Iinclude/libxl -Iinclude/ini -I.
LDFLAGS= -L$(ORACLE_HOME)/lib -Llib -Wl,-rpath,lib
LIBS = -lframe -lini -lsql -loci -lexp -ljson-c -lclntsh -lcutil -luuid -lcaptcha -lxl -lfold -lm

ALL_SRCS = app_proc.c action_handler.c custom_handler.c gen_sql.c data_acl.c md5.c json_ext.c http_util.c secuLib_wst.c parafile.c crc32.c

ALL_CFILES = $(ALL_SRCS:.pc=.c)
ALL_OBJS = $(ALL_CFILES:.c=.o)

PC_SRCS = $(filter %.pc,$(ALL_SRCS))
PC_CFILES = $(PC_SRCS:.pc=.c)

all: tms

tms: $(ALL_OBJS)
	$(CC) $(ALL_OBJS) -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

%c: %pc
	proc $< $@ unsafe_null=yes mode=oracle dbms=v8 parse=full include=\(include/cutil,include/json-c\)

%o: %c
	$(CC) $(CFLAGS) -c -o $@ $<
	#iconv -f GBK -t UTF-8 $< -o $(basename $<)-utf8$(suffix $<)
	#$(CC) $(CFLAGS) -c -o $@ $(basename $<)-utf8$(suffix $<)

clean: 
	rm -f *~ *.lis *.log $(ALL_OBJS) $(PC_CFILES)
	find . -name "*-utf8*"|xargs rm -f


