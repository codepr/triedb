/* BSD 2-Clause License
 *
 * Copyright (c) 2018, Andrea Giacomo Baldan All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include "util.h"
#include "queue.h"


static int queue_free(struct queue_item *qitem) {

    if (!qitem)
        return -1;

    while (queue_free(qitem->next) > 0);

    if (qitem->data)
        tfree(qitem->data);

    tfree(qitem);

    return 0;
}

/*
 * Create a new queue, specifying a custom destructor for items that it will
 * store. In case of NULL the queue will fallback to the default destructor
 * which will just free all queue items
 */
Queue *queue_create(destructor *destr) {

    Queue *q = tmalloc(sizeof(*q));

    if (!q)
        return NULL;

    q->len = 0LL;
    q->front = q->rear = NULL;

    q->destr = destr ? destr : queue_free;

    return q;
}

/* Call the queue destructor on all queue_items */
void queue_release(Queue *q) {

    if (!q)
        return;

    q->destr(q->front);

    tfree(q);
}


size_t queue_size(Queue *q) {
    return q->len;
}


bool queue_empty(Queue *q) {
    return q->len == 0;
}

/* Insert data on the rear item */
void queue_push(Queue *q, void *data) {

    struct queue_item *new_item = tmalloc(sizeof(*new_item));

    if (!new_item) {
        perror("malloc(3) failed");
        exit(EXIT_FAILURE);
    }

    new_item->next = NULL;
    new_item->data = data;
    q->len++;

    if (q->front == NULL && q->rear == NULL) {
        q->front = new_item;
        q->rear = new_item;
    } else {
        q->rear->next = new_item;
        q->rear = new_item;
    }
}


/* Remove data from the front item and deallocate it */
void *queue_get(Queue * q) {

    if (queue_empty(q))
        return NULL;

    void *item = NULL;
    struct queue_item *del_item;
    del_item = q->front;
    q->front = q->front->next;

    if (!q->front)
        q->rear = NULL;

    item = del_item->data;
    if (del_item)
        tfree(del_item);

    q->len--;

    return item;
}
