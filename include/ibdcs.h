#ifndef __IBDCS__H__

#define __IBDCS__H__



#include "folder.h"

//#include "iso8583.h"


#define IBDCS_SHM_NAME      "IbDC"

#define MONITOR_FOLD_NAME   "Monitor"

#define APPSRV_FOLD_NAME   "ISAN"

#define DCSCOM_FOLD_NAME    "DCSBANK"


#define  DELIMITER     " \t=;"

/*IBDCS系统配置参数*/



#define DCS_KEY_SIZE  8

typedef struct tagIbdcsCfg

{

    /*共享内存中超时表的记录数*/

    int iTbTRows;                  /* 超时表中的记录条数*/



    /*超时时间*/

    int iT1;  /*建链请求的超时*/

    int iT2;  /*结束请求的超时*/

    int iT3;  /*交易超时的请求*/

    int    iRunMode; /*运行模式:0--调试模式;1--生产模式*/

} IBDCS_CFG;



#define TIMEOUT1        20

#define TIMEOUT2        21

#define TIMEOUT3        22

#define RUN_MODE        24



/*超时表的记录格式*/

typedef struct eventqueue TBT_AREA;

typedef struct eventitem  TBT_BUF;



#define  TBT_STAT_USED          0x0001



#define  MAX_CHILDREN_NUM       100



/*layout of shared memory in IBDCS*/

typedef struct tagIbdcsShm

{

    int           is_semid;     /*含3个分量的信号量;*/

                                /*0号分量用来互斥访问共享内存中的*/

                                /*is_stat区; 1,2号分量用来访问超时表部分*/

    int           is_MoniPid;   /*monitor进程的pid*/

    int           is_nchld;     /*子进程的个数*/

    int           is_children[MAX_CHILDREN_NUM]; /*各子进程的pid*/

    IBDCS_CFG     is_config;    /*系统配置参数区*/

 //   TBT_AREA      is_tmTbl;     /*超时表*/

}IBDCSSHM;



#define MAX_IBDCS_MSG_SIZE 2048



struct IBDCSPacket

{

    short  pkt_cmd;     /*请求包命令,定义见下*/

    short  pkt_val;     /*请求的数据,含义依赖于不同的命令*/

    long   pkt_bytes;   /*请求数据区中的字节数*/

    char   pkt_buf[1];  /*请求的数据区,含义依赖于不同的命令*/

};

/*用在超时控制中*/

struct savedtxn              /*保存原始请求保文的数据格式*/

 {

    int fromfid;   /* 该报文从哪个文件夹发送来的*/

    int bytes ;    /*报文的字节长度*/

    int databuf[1];   /* 报文内容*/

};



struct CFGTBL {

  char caSubSystem[8];		/* 子系统代号
*/
				            /* DCS:通讯子系统
*/
				            /* TPA:交易子系统
*/
				            /* ISA:交换子系统
*/
  int  iMaxForkNo;		    /* 允许FORK的最大进程数
*/
  int  iMinForkNo;		    /* 第一次Fork的进程数
*/
  int  iUnForkNo;		    /* 未被Fork的进程数
*/
  int  iUnFkIdx;		    /* 下一个被Fork的进程在进程表中的索引号
*/
  char caPrgName[40];  /* 程序名称
*/
  char caPara[80];	    /* 程序所�:枰牟问�
*/
  char caRemark[100];       /*启动进程提示信息
*/
};



#define PKT_CMD_TCPCONN         1000   /*tcp链路状态发生改变*/

#define PKT_CMD_DATAFROMSWITCH  1002   /*来自交换中心的交易数据*/

#define PKT_CMD_CYHREQ          1003   /*发送成员行开始请求*/

#define PKT_CMD_BUSIDOWN        1004   /*业务系统结束交易*/

#define PKT_CMD_DATATOSWITCH    1005   /*发往交换中心的交易数据*/

#define PKT_CMD_TIMER           1006

#define PKT_CMD_TMOUT           1007

extern IBDCSSHM     *g_pIbdcsShm;

extern IBDCS_CFG    *g_pIbdcsCfg;

extern TBT_AREA     *g_pTimeoutTbl;

extern unsigned long g_seqNo;



/*dcs_log.c*/

int  dcs_log_open(const char * logfile, char *ident);

int  dcs_set_logfd(int fd);

void dcs_log_close(void);

void dcs_log(void *pbytes, int nbytes,const char * message, ...);

void dcs_debug(void *pbytes, int nbytes,const char * message, ...);

void dcs_dump(void *pbytes, int nbytes,const char * message,...);



/*int dcs_chkmsg.c*/



/*dcs_shminit.c*/

int dcs_delete_shm(void);

int dcs_create_shm(int tblrows);

int dcs_connect_shm(void);



/*dcs_sysconf.c*/

int dcs_load_config(IBDCS_CFG *pIbdcsCfg);

int dcs_set_sysconf(int which, int val);

int dcs_dump_sysconf(FILE *fpOut);



/*dcs_sysstat.c*/

int dcs_get_sysstat(int which, int* val);

int dcs_set_sysstat(int which, int val);

int dcs_dump_sysstat(FILE *fpOut);



/*dcs_seqno.c*/

int dcs_save_seqNo(void);

unsigned long dcs_make_seqNo(void);



/*from dcs_sock.c*/

extern int tcp_open_server(const char *listen_addr, int listen_port) ;

extern int tcp_accept_client(int listensock,int *cliaddr, int *cliport);

extern int tcp_connet_server(char *servaddr, int servport, int cliport);

extern int tcp_close_socket(int sockfd);

extern int tcp_check_readable(int conn_sockfd,int ntimeout);

extern int tcp_check_writable(int conn_sockfd,int ntimeout);

extern int tcp_read_nbytes(int conn_sock, void *buffer, int nbytes);

extern int tcp_write_nbytes(int conn_sock, const void *buffer, int nbytes);

extern int read_msg_from_net(int connfd,void *msgbuf,int nbufsize,int ntimeout);

extern int write_msg_to_net(int connfd,void *msgbuf, int nbytes,int ntimeout);

extern int tcp_pton(char *strAddr);



#endif /*__IBDCS__H__*/

