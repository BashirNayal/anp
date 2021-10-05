#include<pthread.h>
#include "timer.h"

extern pthread_mutex_t send_lock;
extern pthread_mutex_t recv_lock;
extern pthread_cond_t  send_not_empty;
extern pthread_cond_t  ack_received;
extern pthread_mutex_t syn_lock;
extern pthread_cond_t syn_ack_received;
extern pthread_cond_t done_transmit;
extern pthread_mutex_t transmit;
extern pthread_mutex_t send_wait_lock;
extern pthread_cond_t send_wait_cond;
extern pthread_cond_t recv_wait_cond;

// pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
// pthread_mutex_t recv_lock = PTHREAD_MUTEX_INITIALIZER;
// pthread_cond_t  send_not_empty = PTHREAD_COND_INITIALIZER;
// pthread_cond_t  ack_received = PTHREAD_COND_INITIALIZER;
// pthread_mutex_init(&lock, NULL)