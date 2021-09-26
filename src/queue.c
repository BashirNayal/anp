#include "subuff.h"
#include "queue.h"

void test() {


    struct subuff *sub = alloc_sub(0);
    sub->len = 1;
    // struct subuff_head *head = malloc(sizeof(struct subuff_head));
    struct subuff_head *head = send_queue;
    
    sub_queue_init(head);
    sub_queue_tail(head , sub);
    sub = alloc_sub(0);
    sub->len = 2;
    sub_queue_tail(head , sub);
    sub = alloc_sub(0);
    sub->len = 3;
    sub_queue_tail(head , sub);
    sub = alloc_sub(0);
    sub->len = 4;
    sub_queue_tail(head , sub);
    sub = alloc_sub(0);
    sub->len = 5;
    sub_queue_tail(head , sub);
    sub = alloc_sub(0);
    sub->len = 6;
    sub_queue_tail(head , sub);

    // sub = sub_dequeue(head);
    while(sub_queue_len(head) > 0) {
        sub = sub_dequeue(head);
        printf("%d\n" , sub->len);
        sleep(1);
    }
}
