#include "base.h"

extern session* create_session( shm_data *ptr );
extern session* get_session( shm_data *ptr ,int ndx ,char *key);

extern session* confirm_login_session( shm_data *ptr ,int ndx ,char *key);
extern int del_session( shm_data *ptr ,int ndx ,char *key);
extern int job_working(JOB *job ,void *buf, int len);