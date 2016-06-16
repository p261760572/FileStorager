#ifndef __IBDCS__H__

#define __IBDCS__H__



#include "folder.h"

//#include "iso8583.h"


#define IBDCS_SHM_NAME      "IbDC"

#define MONITOR_FOLD_NAME   "Monitor"

#define APPSRV_FOLD_NAME   "ISAN"

#define DCSCOM_FOLD_NAME    "DCSBANK"


#define  DELIMITER     " \t=;"

/*IBDCSϵͳ���ò���*/



#define DCS_KEY_SIZE  8

typedef struct tagIbdcsCfg

{

    /*�����ڴ��г�ʱ���ļ�¼��*/

    int iTbTRows;                  /* ��ʱ���еļ�¼����*/



    /*��ʱʱ��*/

    int iT1;  /*��������ĳ�ʱ*/

    int iT2;  /*��������ĳ�ʱ*/

    int iT3;  /*���׳�ʱ������*/

    int    iRunMode; /*����ģʽ:0--����ģʽ;1--����ģʽ*/

} IBDCS_CFG;



#define TIMEOUT1        20

#define TIMEOUT2        21

#define TIMEOUT3        22

#define RUN_MODE        24



/*��ʱ���ļ�¼��ʽ*/

typedef struct eventqueue TBT_AREA;

typedef struct eventitem  TBT_BUF;



#define  TBT_STAT_USED          0x0001



#define  MAX_CHILDREN_NUM       100



/*layout of shared memory in IBDCS*/

typedef struct tagIbdcsShm

{

    int           is_semid;     /*��3���������ź���;*/

                                /*0�ŷ�������������ʹ����ڴ��е�*/

                                /*is_stat��; 1,2�ŷ����������ʳ�ʱ������*/

    int           is_MoniPid;   /*monitor���̵�pid*/

    int           is_nchld;     /*�ӽ��̵ĸ���*/

    int           is_children[MAX_CHILDREN_NUM]; /*���ӽ��̵�pid*/

    IBDCS_CFG     is_config;    /*ϵͳ���ò�����*/

 //   TBT_AREA      is_tmTbl;     /*��ʱ��*/

}IBDCSSHM;



#define MAX_IBDCS_MSG_SIZE 2048



struct IBDCSPacket

{

    short  pkt_cmd;     /*���������,�������*/

    short  pkt_val;     /*���������,���������ڲ�ͬ������*/

    long   pkt_bytes;   /*�����������е��ֽ���*/

    char   pkt_buf[1];  /*�����������,���������ڲ�ͬ������*/

};

/*���ڳ�ʱ������*/

struct savedtxn              /*����ԭʼ�����ĵ����ݸ�ʽ*/

 {

    int fromfid;   /* �ñ��Ĵ��ĸ��ļ��з�������*/

    int bytes ;    /*���ĵ��ֽڳ���*/

    int databuf[1];   /* ��������*/

};



struct CFGTBL {

  char caSubSystem[8];		/* ��ϵͳ����
*/
				            /* DCS:ͨѶ��ϵͳ
*/
				            /* TPA:������ϵͳ
*/
				            /* ISA:������ϵͳ
*/
  int  iMaxForkNo;		    /* ����FORK����������
*/
  int  iMinForkNo;		    /* ��һ��Fork�Ľ�����
*/
  int  iUnForkNo;		    /* δ��Fork�Ľ�����
*/
  int  iUnFkIdx;		    /* ��һ����Fork�Ľ����ڽ��̱��е�������
*/
  char caPrgName[40];  /* ��������
*/
  char caPara[80];	    /* �������:�Ҫ�Ĳ���
*/
  char caRemark[100];       /*����������ʾ��Ϣ
*/
};



#define PKT_CMD_TCPCONN         1000   /*tcp��·״̬�����ı�*/

#define PKT_CMD_DATAFROMSWITCH  1002   /*���Խ������ĵĽ�������*/

#define PKT_CMD_CYHREQ          1003   /*���ͳ�Ա�п�ʼ����*/

#define PKT_CMD_BUSIDOWN        1004   /*ҵ��ϵͳ��������*/

#define PKT_CMD_DATATOSWITCH    1005   /*�����������ĵĽ�������*/

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
