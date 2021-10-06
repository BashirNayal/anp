/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdio.h>
#include <stdbool.h>
#include "systems_headers.h"
#include "tap_netdev.h"
#include "anp_netdev.h"
#include "route.h"
#include "anpwrapper.h"
#include "timer.h"
#include "sync.h"
#include "queue.h"

extern char**environ;

#define THREAD_RX      0
#define THREAD_TIMER   1
#define THREAD_TX      2
#define THREAD_MAX     3

static pthread_t threads[THREAD_MAX];

static void create_thread(pthread_t id, void *(*func) (void *))
{
    int ret = pthread_create(&threads[id], NULL, func, NULL);
    if ( 0 != ret) {
        printf("thread creation failed %d , errno %d \n", ret, errno);
        exit(-errno);
    }
}

void ctrl_c_handler(int val) {
    printf("Good bye, cruel world \n");
    stop = true;
}

static void init_threads()
{

    pthread_mutex_init(&send_lock , NULL);
    pthread_mutex_init(&recv_lock , NULL);
    pthread_cond_init(&send_not_empty , NULL);
    pthread_cond_init(&ack_received , NULL);
    pthread_cond_init(&syn_ack_received , NULL);
    pthread_cond_init(&done_transmit , NULL);
    pthread_mutex_init(&syn_lock , NULL);
    pthread_mutex_init(&transmit , NULL);
    pthread_mutex_init(&send_wait_lock , NULL);
    pthread_cond_init(&send_wait_cond , NULL);
    pthread_cond_init(&recv_wait_cond , NULL);
    pthread_cond_init(&close_wait_cond , NULL);
    send_queue = malloc(sizeof(struct subuff_head));
    sub_queue_init(send_queue);
    recv_queue = malloc(sizeof(struct subuff_head));
    sub_queue_init(recv_queue);


    // we have two async activities
    create_thread(THREAD_RX, netdev_rx_loop);
    create_thread(THREAD_TIMER, timers_start);
    create_thread(THREAD_TX , send_to_socket);

}

void __attribute__ ((constructor)) _init_anp_netstack() {
    //https://stackoverflow.com/questions/3275015/ld-preload-affects-new-child-even-after-unsetenvld-preload
    // uff, what a mess. So, if there are exec (which is in the system call, it fork bombs, hence it is
    // quite important to unset thr LD_PRELOAD once we are here
#ifdef ANP_DEBUG
    int i;
    printf("Unsetting LD_PRELOAD: %x\n", unsetenv("LD_PRELOAD"));
    printf("LD_PRELOAD: \"%s\"\n", getenv("LD_PRELOAD"));
    printf("Environ: %lx\n",environ);
    printf("unsetenv: %lx\n",unsetenv);
    for (i=0;environ[i];i++ ) printf("env: %s\n",environ[i]);
    fflush(stdout);
#else
    unsetenv("LD_PRELOAD");
#endif
    printf("Hello there, I am ANP networking stack!\n");
    _function_override_init();
    // this is the external end, at 10.0.0.5
    tdev_init();
    // this is the client end, at 10.0.0.4
    client_netdev_init();
    // insert and init some default routes about, lo, local delivery, and the gateway
    route_init();
    init_threads();
}