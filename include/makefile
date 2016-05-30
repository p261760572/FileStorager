#LIBS=$(LIB) -L$(HOME)/lib  -ldcsutil -ltimer -liso8583 -lfold -lsecu -ldbconn
LIBS=$(LIB) -L$(HOME)/lib  -ldcsutil -ltimer -liso8583 -lfold -lsecu 
BIN =$(ICS_HOME)/bin
CFLAGS=-I $(HOME)/include 
ORACLE_LIB= -L$(ORACLE_HOME)/lib -lsqlplus -lclntsh
#OBJ =main.o request_proc.o respose_proc.o app_proc.o unpack.o util.o define_data.o  \
#   pack.o tpos_unpack.o load_config.o timeout_proc.o db_qfunc.o db_ifunc.o db_ufunc.o \
#   db_dfunc.o db_dssfunc.o iso_pack.o iso_unpack.o tpos_pack.o tpos_util.o
OBJ = define_data.o tpos_util.o db_tpos_qfunc.o db_tpos_ufunc.o
#EXE = TransRcv 
EXE =  termsvr
LIBOBJ=main.o request_proc.o respose_proc.o app_proc.o unpack.o util.o \
      pack.o tpos_unpack.o load_config.o timeout_proc.o db_qfunc.o db_ifunc.o db_ufunc.o \
      db_dfunc.o db_dssfunc.o iso_pack.o iso_unpack.o tpos_pack.o XmlMessage.o util_db.o
.c.o:
	$(CC) -c -Wstrict-prototypes $(CFLAGS) $*.c

exe:    $(EXE) cleanup
all:    $(OBJ) lib $(EXE) cleanup
lib: $(LIBOBJ) 
	$(AR) $(ARFLAGS) libapp.a  $(LIBOBJ) 

db_dssfunc.c:db_dssfunc.pc
	proc db_dssfunc.pc db_dssfunc.c unsafe_null=yes   mode=oracle dbms=v8 include=$(HOME)/include  
db_qfunc.c:db_qfunc.pc
	proc db_qfunc.pc db_qfunc.c unsafe_null=yes   mode=oracle dbms=v8 include=$(HOME)/include  
db_ifunc.c:db_ifunc.pc
	proc db_ifunc.pc db_ifunc.c unsafe_null=yes   mode=oracle dbms=v8 include=$(HOME)/include  
db_ufunc.c:db_ufunc.pc
	proc db_ufunc.pc db_ufunc.c unsafe_null=yes   mode=oracle dbms=v8 include=$(HOME)/include
db_dfunc.c:db_dfunc.pc
	proc db_dfunc.pc db_dfunc.c unsafe_null=yes   mode=oracle dbms=v8 include=$(HOME)/include    
db_tpos_qfunc.c:db_tpos_qfunc.pc
	proc db_tpos_qfunc.pc db_tpos_qfunc.c unsafe_null=yes   mode=oracle dbms=v8 include=$(HOME)/include    
db_tpos_ufunc.c:db_tpos_ufunc.pc
	proc db_tpos_ufunc.pc db_tpos_ufunc.c unsafe_null=yes   mode=oracle dbms=v8 include=$(HOME)/include    
XmlMessage.c:XmlMessage.pc
	proc XmlMessage.pc XmlMessage.c unsafe_null=yes   mode=oracle dbms=v8 include=$(HOME)/include   
termsvr: $(OBJ)
	gcc -Wstrict-prototypes -o termsvr $(CFLAGS) $(OBJ) -L. -lapp $(LIBS) $(ORACLE_LIB)
	mv termsvr ../run/bin

cleanup:
	rm -f *.o dssdclfn.c db_*.c XmlMessage.c *.lis




