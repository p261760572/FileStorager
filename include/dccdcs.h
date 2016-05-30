#ifndef DCCDCS_H
#define DCCDCS_H

#include <folder.h>


// 定义收件夹名称
#define DCS_CASHMEM_NAME      "CashMem"   
#define DCS_CASHREC_NAME        "ISAN"
#define DCS_CASHMAG_NAME       "CashMag"
#define DCS_POSSRV_FOLD_NAME   "PosSvr"
#define DCS_BCDA_NAME          "BCDA"
#define DCS_POSCOM_NAME        "STCP"
#define   DCS_FLAG_USED           0x00000001 //占用标志
#define   DCS_FLAG_DIRECT         0x00000002 //POS和中心直联

#define   DCS_ROLE_PASSIVE        1 //被动（passive）角色
#define   DCS_ROLE_ACTIVE         2 //主动(active)角色

#define   DCS_STAT_DISCONNECTED   0 //已经处于连接状态
#define   DCS_STAT_CALLING        1 //正在呼叫 
#define   DCS_STAT_LISTENING      2 //正在监听
#define   DCS_STAT_CONNECTED      3 //已经处于连接状态
#define   DCS_STAT_STOPPED        4 //处于停止状态

//for termcom
#define   DCS_STAT_READNET        5 //正在读网络
#define   DCS_STAT_WRITENET       6 //正在写网络
#define   DCS_STAT_READFOLD       7 
#define   DCS_STAT_WRITEFOLD      8 
#define   DCS_STAT_WAITREQ        9
#define   DCS_STAT_SENDREQ        10
#define   DCS_STAT_WAITRESP       11 

//HstSrv接收的消息类型
#define	  DCS_LINKESTAB_NOTI      1001 //来自通信进程的链路建立通知
#define	  DCS_COMMAND_LINE        1002 //来自命令行接口的请求


//来自命令行接口的命令种类
#define   DCS_CMD_STOP            1   //停止一条处于连接态的链路
#define   DCS_CMD_START           2   //启动一条处于停止态的链路
#define   DCS_CMD_EXIT            3   //服务器退出运行
#define   DCS_CMD_ADD             4   //增加一条链路
#define   DCS_CMD_MODIFY          5   //修改一条链路
#define   DCS_CMD_DEL             6   //修改一条链路


// 报文头类型

#define DCS_HEAD_TRM              1
#define DCS_HEAD_BANK             2
#define DCS_HEAD_ZFY              3
#define DCS_HEAD_AMP              4
#define DCS_HEAD_TRM1             5
struct trmgrpinfo
{
	char caFoldName[MAX_FOLDNAME_SIZE + 1];
	long lFlags;         //标志字
	int    iFid;
	pid_t pidComm;      //进程号
	short  iStatus;     //该terminal当前 的状态
  char    sRemoteIp[16];   //实际的远端的IP地址
  int    iRemotePort; //实际的远端的端口号
  int    iLocalPort;  //本地端口  
};
struct trminfo
{
    char   caFoldName[MAX_FOLDNAME_SIZE + 1];
                        //该terminal对应文件夹的名字
    int    iGid;        //组号
    int    iFid;         
    int    iApplFid;
    int    iRole;               
    long   lFlags;      //该terminal的标志字
    short  iStatus;     //该terminal当前 的状态
    int    maxterm;
    int    minterm;
    int    iShmId;
    pid_t  pidComm;     //该terminal对应的TCP进程的Id
    int    iType ;      //通讯方式，主动还是被动    
    char   sMsgType[5];  //报文类型
    int    iHeadType;    //报文头类型 
    char   sRemoteIp[16];   //实际的远端的IP地址
    int    iRemotePort; //实际的远端的端口号
    int    iLocalPort;  //本地端口    
    struct trmgrpinfo *trmArray;
};

struct trmcom
{
    int    iTrmCnt;  //elements# in array trmArray[]
    int    iShmId;
    struct trminfo linkArray[1]; 
};

//
//TrmSvr接收的消息类型
//
struct trmrequest     //通用格式
{
  char caMsgType[4];  //消息类型
  char caMsgData[1];  //消息数据
};

struct hstrequest     //通用格式
{
  char caMsgFlag[4];  // 命令标志:"ISEI"
  char caMsgType[4];  //消息类型
  char caMsgData[1];  //消息数据
};

// comunication cortrol table(BCDA)
struct BCDA
{
  char caBankCode[11];// 成员行代码
  int  iBankSeq;// 成员行的顺序号，用作信号分量
  char caBankName[15];// 成员行名称
  char cNetFlag;// 网络连接数目
  char cAppFlag;            // 应用连接标志
  char cSafFlag;            // 存储转发标志
  char cResetKeyFlag;       // 重置密钥标志
  char ReadFlag;          // 数据接收链路标志
  char SendFlag;          // 数据发送链路标志
  int  iDaySwhMaxTries;     // 重发日切开始请求的最大尝试次数
  char caType[8];           // The Type of "sh p POSI ICSC"

};

struct BCDAst
{
  int    iSemId;            //信号灯标识号,用于互斥访问
  int    iBankNum;          // 成员行数目
  struct BCDA stBcda[1];    // BCDA的首地址
};


struct commnotify     //Tcpip进程的通知格式
{
  char caMsgFlag[4];  // 命令标志:"ISEI"
  char caMsgType[4];  //消息类型
  char caFoldName[4]; //文件夹名称即链路名称
  int  iCommPid;
  int  iStatus;       //链路当前状态,0表示断开,1表示建立
};

struct trmcmd         //命令行接口来的请求格式
{
  char caMsgFlag[4];  // 命令标志:"ISEI"
  char caMsgType[4];  //消息类型
  char caFoldName[30]; //文件夹名称即链路名称
  int  iCommand;      //具体的命令
};


char   *g_pcBcdaShmPtr;             // 共享内存BCDA的首地址

#endif
