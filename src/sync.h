#include<pthread.h>

static pthread_mutex_t send_lock;
static pthread_mutex_t recv_lock;
static pthread_cond_t  send_not_empty;
static pthread_cond_t  ack_received;

// pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
// pthread_mutex_t recv_lock = PTHREAD_MUTEX_INITIALIZER;
// pthread_cond_t  send_not_empty = PTHREAD_COND_INITIALIZER;
// pthread_cond_t  ack_received = PTHREAD_COND_INITIALIZER;
// pthread_mutex_init(&lock, NULL)