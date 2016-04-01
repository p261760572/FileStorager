#ifndef _FDEVENT_H_
#define _FDEVENT_H_

#include "settings.h"
#include "bitset.h"



#include <sys/types.h>
#include <sys/select.h>

struct server;

typedef handler_t (*fdevent_handler)(struct server *srv, void *ctx, int revents);

/* these are the POLL* values from <bits/poll.h> (linux poll)
 */

#define FDEVENT_IN     BV(0)
#define FDEVENT_PRI    BV(1)
#define FDEVENT_OUT    BV(2)
#define FDEVENT_ERR    BV(3)
#define FDEVENT_HUP    BV(4)
#define FDEVENT_NVAL   BV(5)

typedef enum { FD_EVENT_TYPE_UNSET = -1,
		FD_EVENT_TYPE_CONNECTION,
		FD_EVENT_TYPE_FCGI_CONNECTION,
		FD_EVENT_TYPE_DIRWATCH,
		FD_EVENT_TYPE_CGI_CONNECTION
} fd_event_t;

typedef enum { 
	  FDEVENT_HANDLER_UNSET,
		FDEVENT_HANDLER_SELECT,
		FDEVENT_HANDLER_POLL,
		FDEVENT_HANDLER_LINUX_SYSEPOLL,
		
} fdevent_handler_t;


typedef struct _fdnode {
	fdevent_handler handler;
	void *ctx;
	void *handler_ctx;
	int fd;
	int events;
} fdnode;

/**
 * array of unused fd's
 *
 */

typedef struct {
	int *ptr;

	size_t used;
	size_t size;
} buffer_int;

/**
 * fd-event handler for select(), poll() and rt-signals on Linux 2.4
 *
 */
typedef struct fdevents {
	struct server *srv;
	fdevent_handler_t type;

//	fdnode **fdarray;
	size_t maxfds;

	fd_set select_read;
	fd_set select_write;
	fd_set select_error;

	fd_set select_set_read;
	fd_set select_set_write;
	fd_set select_set_error;
	int select_max_fd;
	int (*reset)(struct fdevents *ev);
	void (*free)(struct fdevents *ev);
	int (*event_set)(struct fdevents *ev, int fde_ndx, int fd, int events);
	int (*event_del)(struct fdevents *ev, int fd);
	int (*event_get_revent)(struct fdevents *ev, size_t ndx);
	int (*event_get_fd)(struct fdevents *ev, size_t ndx);
	int (*event_next_fdndx)(struct fdevents *ev, int ndx);
	int (*poll)(struct fdevents *ev, int timeout_ms);
	int (*fcntl_set)(struct fdevents *ev, int fd);
} fdevents;

fdevents *fdevent_init(struct server *srv, size_t maxfds, fdevent_handler_t type);
int fdevent_reset(fdevents *ev); /* "init" after fork() */
void fdevent_free(fdevents *ev);

int fdevent_event_set(fdevents *ev, int *fde_ndx, int fd, int events); /* events can be FDEVENT_IN, FDEVENT_OUT or FDEVENT_IN | FDEVENT_OUT */
int fdevent_event_del(fdevents *ev, int fd);
int fdevent_event_get_revent(fdevents *ev, size_t ndx);
int fdevent_event_get_fd(fdevents *ev, size_t ndx);
fdevent_handler fdevent_get_handler(fdevents *ev, int fd);
void * fdevent_get_context(fdevents *ev, int fd);

int fdevent_event_next_fdndx(fdevents *ev, int ndx);

int fdevent_poll(fdevents *ev, int timeout_ms);

int fdevent_register(fdevents *ev, int fd, fdevent_handler handler, void *ctx);
int fdevent_unregister(fdevents *ev, int fd);

int fdevent_fcntl_set(fdevents *ev, int fd);

int fdevent_select_init(fdevents *ev);

#endif
