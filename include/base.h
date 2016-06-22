#ifndef _BASE_H_
#define _BASE_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <limits.h>
#include "settings.h"
#include "buffer.h"

#include "fdevent.h"
#include "array.h"


#define MAX_JOB 100
/* fcgi_response_header contains ... */
#define HTTP_STATUS         BV(0)
#define HTTP_CONNECTION     BV(1)
#define HTTP_CONTENT_LENGTH BV(2)
#define HTTP_DATE           BV(3)
#define HTTP_LOCATION       BV(4)

typedef struct
{
    struct sockaddr_in addr;
    int       fd;
    int       fde_ndx;
} server_socket;

typedef struct
{
    server_socket ptr[5];

//  size_t size;
    size_t used;
} server_socket_array;

#define  FIRST   1
#define  SECEND  2;

typedef struct
{

    /* timestamps */
    time_t read_idle_ts;
    time_t close_timeout_ts;
    time_t connection_start;
    time_t request_start;
//  struct timeval start_tv;
    size_t request_count;        /* number of requests handled in this connection */
    int fd;                      /* the FD for this connection */
//  int fde_ndx;                 /* index for the fdevent-handler */
//  int ndx;                     /* reverse mapping to server->connection[ndx] */
    /* fd states */
    int head_len;
    int is_readable;
    int is_writable;
    int used;               /*使用标识 0, 未使用 1使用*/
    int state;             /*状态 指示一次事务的数据是否已经收取完整，
                            0，未开始，1正在接收中，2，完成数据接收 */
    int type;            /*表示一次事务的数据长度格式类型 1、两字节标识长度
                         2、四字节标识长度
                         3、http协议标识的长度 */
    int mode;            /* 表示socket是否应用socket还是监控新连接的socket*/
    int msg_len;         /* 解析报文得到的包体长度 */
    int data_len;        /*收到的真实数据长度 */
    struct sockaddr_in dst_addr;
    unsigned char buf[1024*16];

} connection;

typedef struct
{
    connection *ptr;
    size_t size;
} connections;

typedef struct
{
    int port;
    int type;
    int timeout;
} srv_socket;

typedef struct
{
    srv_socket *srv_socks;
    int srv_sock_cnt;  /*sock已分配位置*/
    int used;    /* sock已使用位置  */
    int shm_rows;    /*共享内存配置的记录最大数*/
    char config_file_name[512];
    char log_file_name[512];
} config;

typedef struct server
{

    config  cfg;
    fdevents ev;
    int dont_daemon;

    int max_workers;
    int max_fds;    /* max possible fds */
    int cur_fds;    /* currently used fds */
    size_t max_conns;
    time_t startup_ts;
    connections conns;
    void *shm_ptr;
    fdevent_handler_t event_handler;

} server;
/* 会话数据的组成以ndx+key组成
   1、新会话以seqno作为散列的的方式确定该会话存放位置。
   2、老会话以ndx作为查找该会话所在位置，并对该位置的可以进行比较以核准会话的合法性
*/
typedef struct session
{
    char ip[15+1];
    char name[32+1];
    char key[128+1];
    char login_flag;   // 在客户端登录时先申请服务端产生的随机数用于
//  对客户端输入的密码加密使用，本阶段缓冲区在密码验证阶段超时时间只有10秒，要求客户端在输入用户名和密码
// 后先发起交互随机数指令，在使用登录指令
    int  ndx;    /*索引号*/
    int  used;   /*使用标记*/
//  unsigned long seqno;  /*产生的顺序号*/
//  unsigned int rand;   /*用于对顺序号进行混杂*/
//  char     method ;         /*混杂方法  */
    time_t build_time;
    time_t last_time;
    time_t idle_time;
    char remark[512];
} session;

typedef struct shm_data
{
    int max_rows;
    int sem_lock;
    int last_ndx;
    session ptr[1];
} shm_data;

typedef struct JOB
{
    int sock_id;
    int fd;
    int read_or_write; //读操作，还是写操作
    time_t last_time;  //最后处理时间
    long file_size;    //文件大小
    long off_set;      //已传输文件内容偏移量
    char file_name[128];
    char file_path[256];
    char file_head[64];
    char cache_buf[90];
    char remark[512];
    int remark_len;
    int (*begin_proc)(int sock_id,int fd,char  *file_name,char  *file_path,char *cache_buf,char *file_cache, char *remark,long *off_set, long *file_size,void *buf,int buf_len);
    int (*every_proc)(int sock_id, char *file_name ,char *file_path, long off_set, char *remark);//每一次通信事务完成的应用处理
    int (*end_proc)(int sock_id, char *file_name ,char *file_path, long off_set,char *remark);//通信全部完成后的应用处理
    int (*error_proc)(int sock_id, char *file_name ,char *file_path, long off_set, char *remark);//处理中出错的应用处理
} JOB;

typedef struct JOB_LIST
{
    int num;
    JOB workers[MAX_JOB];
} JOB_LIST;

#endif

