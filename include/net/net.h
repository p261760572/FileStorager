#ifndef __net_h
#define __net_h

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>  // For inet_pton() when NS_ENABLE_IPV6 is defined
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>

#ifdef NET_ENABLE_SSL
#include <openssl/ssl.h>
#else
typedef void *SSL;
typedef void *SSL_CTX;
#endif


#ifndef NET_MALLOC
#define NET_MALLOC malloc
#endif

#ifndef NET_REALLOC
#define NET_REALLOC realloc
#endif

#ifndef NET_FREE
#define NET_FREE free
#endif

#ifndef NET_CALLOC
#define NET_CALLOC calloc
#endif


#define closesocket(x) close(x)
#define INVALID_SOCKET (-1)
#define to64(x) strtoll(x, NULL, 10)
typedef int sock_t;
typedef struct stat net_stat_t;

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

union socket_address {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

// IO buffers interface
struct iobuf_s {
    char *buf;
    size_t len;
    size_t size;
};

typedef struct iobuf_s iobuf_t;

void iobuf_init(iobuf_t *iobuf, size_t initial_size);
void iobuf_destroy(iobuf_t *iobuf);
size_t iobuf_append(iobuf_t *iobuf, const void *data, size_t data_size);
void iobuf_remove(iobuf_t *iobuf, size_t data_size);


typedef struct net_connection_s net_connection_t;


#define NET_MAX_HOST_SIZE 1024 

// Events. Meaning of event parameter (evp) is given in the comment.
#define NET_POLL    0  // Sent to each connection on each call to net_mgr_poll()
#define NET_ACCEPT  1  // New connection accept()-ed. union socket_address *addr
#define NET_CONNECT 2  // connect() succeeded or failed. int *success_status
#define NET_RECV    3  // Data has benn received. int *num_bytes
#define NET_SEND    4  // Data has been written to a socket. int *num_bytes
#define NET_CLOSE   5  // Connection is closed. NULL

// Callback function (event handler) prototype, must be defined by user.
// Net will call event handler, passing events defined above.
typedef void (*net_event_handler_t)(net_connection_t *, int ev, void *evp);


struct net_mgr_s {
    net_connection_t *active_connections;
    void *user_data;                  // User data
};

typedef struct net_mgr_s net_mgr_t;


struct net_connection_s {
    net_connection_t *next, *prev;  // net_mgr_s::active_connections linkage
    net_connection_t *listener;     // Set only for accept()-ed connections
    net_mgr_t *mgr;

    sock_t sock;                // Socket
    union socket_address sa;    // Peer address
    iobuf_t recv_iobuf;    // Received data
    iobuf_t send_iobuf;    // Data scheduled for sending
    void *user_data;            // User-specific data
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    time_t last_io_time;        // Timestamp of the last socket IO
    net_event_handler_t proto_handler; /* Protocol-specific event handler */
  	void *proto_data;                 /* Protocol-specific data */
    net_event_handler_t handler;     // Event handler function

    unsigned int flags;
};

#define NETF_SEND_AND_CLOSE   		 (1 << 0)
#define NETF_BUFFER_BUT_DONT_SEND    (1 << 1)
#define NETF_CONNECTING              (1 << 2)
#define NETF_CLOSE_IMMEDIATELY       (1 << 3)
#define NETF_LISTENING               (1 << 4)
#define NETF_UDP                     (1 << 5)
#define NETF_SSL_HANDSHAKE_DONE      (1 << 6)	/* SSL specific */
#define NETF_WANT_READ               (1 << 7)	/* SSL specific */
#define NETF_WANT_WRITE              (1 << 8)	/* SSL specific */


#define NETF_USER_1                  (1 << 20)
#define NETF_USER_2                  (1 << 21)
#define NETF_USER_3                  (1 << 22)
#define NETF_USER_4                  (1 << 23)
#define NETF_USER_5                  (1 << 24)
#define NETF_USER_6                  (1 << 25)


// Address format: [PROTO://][IP_ADDRESS:]PORT
int net_parse_address(const char *str, union socket_address *sa, int *proto, char *host, size_t host_len);


void net_mgr_init(net_mgr_t *, void *user_data);
void net_mgr_destroy(net_mgr_t *);
time_t net_mgr_poll(net_mgr_t *, int milli);

net_connection_t *net_next(net_mgr_t *, net_connection_t *);
net_connection_t *net_add_sock(net_mgr_t *, sock_t, net_event_handler_t);
net_connection_t *net_bind(net_mgr_t *, const char *, net_event_handler_t, void *);
net_connection_t *net_connect(net_mgr_t *, const char *, net_event_handler_t, void *);

int net_send(net_connection_t *, const void *buf, size_t len);
int net_vprintf(net_connection_t *nc, const char *fmt, va_list ap);
int net_printf(net_connection_t *, const char *fmt, ...);
const char *net_set_ssl(net_connection_t *nc, const char *cert, const char *ca_cert);


// Utility functions
void *net_start_thread(void *(*f)(void *), void *p);
void net_set_close_on_exec(sock_t);
void net_sock_to_str(sock_t sock, char *buf, size_t len, int flags);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __net_h

