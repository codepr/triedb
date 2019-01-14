/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2018, Andrea Giacomo Baldan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include "list.h"
#include "ringbuf.h"


// Socket families
#define UNIX    0
#define INET    1


typedef struct {
    int epollfd;
    int max_events;
    int timeout;
    int status;
    struct epoll_event *events;
} EpollLoop;


typedef void cb_func(EpollLoop *, void *);

typedef struct {
    int fd;
    void *args;
    cb_func *callback;
} Callback;


/* Set non-blocking socket */
int set_nonblocking(int);

/* Set TCP_NODELAY flag to true, disabling Nagle's algorithm, no more waiting
   for incoming packets on the buffer */
int set_tcp_nodelay(int);

/* Auxiliary function for creating epoll server */
int create_and_bind(const char *, const char *, int);

/*
 * Create a non-blocking socket and make it listen on the specfied address and
 * port
 */
int make_listen(const char *, const char *, int);

/* Accept a connection and add it to the right epollfd */
int accept_connection(int);

/* Open a connection with a target host:port */
int open_connection(const char *, int);

/* Epoll management functions */
EpollLoop *epoll_loop_init(int, int);
void epoll_loop_free(EpollLoop *);
int epoll_loop_wait(EpollLoop *);
void epoll_register_callback(EpollLoop *, Callback *);
void epoll_register_periodic_task(EpollLoop *, int, Callback *);
void epoll_delete_callback(EpollLoop *, int);
int add_epoll(int, int, void *);
int mod_epoll(int, int, int, void *);
int del_epoll(int, int);

/* I/O management functions */
int sendall(int, const uint8_t *, ssize_t, ssize_t *);
int recvall(int, Ringbuffer *, ssize_t);
int recvbytes(int, Ringbuffer *, ssize_t, size_t);

void htonll(uint8_t *, uint_least64_t );
uint_least64_t ntohll(const uint8_t *);

#endif
