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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include "util.h"
#include "server.h"
#include "network.h"


/* Set non-blocking socket */
int set_nonblocking(const int fd) {
    int flags, result;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }
    result = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (result == -1) {
        perror("fcntl");
        return -1;
    }
    return 0;
}


static int create_and_bind_unix(const char *sockpath, const char *port) {

    struct sockaddr_un addr;
    int fd;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path) - 1);
    unlink(sockpath);

    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("bind error");
        return -1;
    }

    return fd;
}


static int create_and_bind_tcp(const char *host, const char *port) {

    const struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    };

    struct addrinfo *result, *rp;
    int sfd;

    if (getaddrinfo(host, port, &hints, &result) != 0) {
        perror("getaddrinfo error");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (sfd == -1) continue;

        /* set SO_REUSEADDR so the socket will be reusable after process kill */
        if (setsockopt(sfd, SOL_SOCKET, (SO_REUSEPORT | SO_REUSEADDR),
                    &(int) { 1 }, sizeof(int)) < 0)
            perror("SO_REUSEADDR");

        if ((bind(sfd, rp->ai_addr, rp->ai_addrlen)) == 0) {
            /* Succesful bind */
            break;
        }
        close(sfd);
    }

    if (rp == NULL) {
        perror("Could not bind");
        return -1;
    }

    freeaddrinfo(result);
    return sfd;
}


int create_and_bind(const char *host, const char *port, int socket_family) {

    int fd;

    if (socket_family == UNIX) {
        fd = create_and_bind_unix(host, port);
    } else {
        fd = create_and_bind_tcp(host, port);
    }

    return fd;
}


/*
 * Create a non-blocking socket and make it listen on the specfied address and
 * port
 */
int make_listen(const char *host, const char *port, int socket_family) {

    int sfd;

    if ((sfd = create_and_bind(host, port, socket_family)) == -1)
        abort();

    if ((set_nonblocking(sfd)) == -1)
        abort();

    if ((listen(sfd, SOMAXCONN)) == -1) {
        perror("listen");
        abort();
    }

    return sfd;
}


int accept_connection(const int serversock) {

    int clientsock;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if ((clientsock = accept(serversock,
                    (struct sockaddr *) &addr, &addrlen)) < 0) {
        return -1;
    }

    set_nonblocking(clientsock);

    char ip_buff[INET_ADDRSTRLEN + 1];
    if (inet_ntop(AF_INET, &addr.sin_addr,
                ip_buff, sizeof(ip_buff)) == NULL) {
        close(clientsock);
        return -1;
    }

    DEBUG("Client connection from %s", ip_buff);

    return clientsock;
}



int sendall(const int sfd, uint8_t *buf, ssize_t len, ssize_t *sent) {
    int total = 0;
    ssize_t bytesleft = len;
    int n = 0;
    while (total < len) {
        n = send(sfd, buf + total, bytesleft, MSG_NOSIGNAL);
        if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            else {
                perror("send(2): error sending data\n");
                break;
            }
        }
        total += n;
        bytesleft -= n;
    }
    *sent = total;
    return n == -1 ? -1 : 0;
}


int recvall(const int sfd, Ringbuffer *ringbuf, ssize_t len) {
    int n = 0;
    int total = 0;
    int bufsize = 256;
    if (len > 0)
        bufsize = len + 1;
    uint8_t buf[bufsize];
    for (;;) {
        if ((n = recv(sfd, buf, bufsize - 1, 0)) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                perror("recv(2): error reading data\n");
                return -1;
            }
        }
        if (n == 0) {
            return 0;
        }
        /* Insert all read bytes in the ring buffer */
        // FIXME check the full ring buffer scenario
        ringbuf_bulk_push(ringbuf, buf, n);

        total += n;
    }
    return total;
}


int recvbytes(const int sfd, Ringbuffer *ringbuf, ssize_t len, size_t bufsize) {
    int n = 0;
    int total = 0;
    uint8_t buf[bufsize];
    while (total < bufsize) {
        if ((n = recv(sfd, buf, bufsize - total, 0)) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                perror("recv(2): error reading data\n");
                return -1;
            }
        }
        if (n == 0) {
            return 0;
        }
        /* Insert all read bytes in the ring buffer */
        // FIXME check the full ring buffer scenario
        ringbuf_bulk_push(ringbuf, buf, n);

        total += n;
    }
    return total;
}


EpollLoop *epoll_loop_init(int max_events) {

    EpollLoop *loop = t_malloc(sizeof(*loop));

    loop->max_events = max_events;
    loop->events = t_malloc(sizeof(struct epoll_event) * max_events);
    loop->epollfd = epoll_create1(1024);
    loop->tasks = list_init();

    // Optional
    loop->default_args = NULL;
    loop->default_task = NULL;

    return loop;
}


void epoll_loop_free(EpollLoop *loop) {
    t_free(loop->events);
    list_free(loop->tasks);
    t_free(loop);
}


void create_task(EpollLoop *loop, int fd, void (*task)(void *ptr), void *args) {

    Task *t = t_malloc(sizeof(*t));
    t->fd = fd;
    t->type = TASK;
    t->args = args;
    t->task = task;

    loop->tasks = list_push(loop->tasks, t);

    add_epoll(loop->epollfd, t->fd, NULL);
}


void create_periodic_task(EpollLoop *loop, int ns, void (*task)(void *ptr), void *args) {

    struct itimerspec timervalue;

    int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

    memset(&timervalue, 0x00, sizeof(timervalue));

    // Set initial expire time and periodic interval
    timervalue.it_value.tv_nsec = ns;
    timervalue.it_interval.tv_nsec = ns;

    add_epoll(loop->epollfd, timerfd, NULL);

    if (timerfd_settime(timerfd, 0, &timervalue, NULL) < 0) {
        perror("timerfd_settime");
        return;
    }

    // Add the timer to the event loop
    struct epoll_event ev;
    ev.data.fd = timerfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(loop->epollfd, EPOLL_CTL_ADD, timerfd, &ev) < 0) {
        perror("epoll_ctl(2): EPOLLIN");
        return;
    }

    Task *t = t_malloc(sizeof(*t));
    t->fd = timerfd;
    t->type = PERIODIC;
    t->args = args;
    t->task = task;

    loop->tasks = list_push(loop->tasks, t);

}


void epoll_loop_wait(EpollLoop *loop) {

    int events = 0;
    ListNode *cursor = NULL;
    Task *t = NULL;
    bool executed = false;

    while ((events = epoll_wait(loop->epollfd,
                    loop->events, loop->max_events, -1)) > -1) {

        for (int i = 0; i < events; i++) {

            executed = false;

            if (loop->events[i].data.fd == config.run) {

                /* And quit event after that */
                eventfd_t val;
                eventfd_read(config.run, &val);

                DEBUG("Stopping epoll loop.");

                break;
            }

            while (cursor) {
                t = cursor->data;
                if (loop->events[i].data.fd == t->fd) {
                    t->task(t->args);
                    executed = true;
                }
                cursor = cursor->next;
            }

            // If no tasks were found, run the default one
            if (executed == false)
                loop->default_task(loop->default_args);
        }
    }

    // FIXME free resources here
    epoll_loop_free(loop);
}


void add_epoll(const int efd, const int fd, void *data) {
    struct epoll_event ev;
    ev.data.fd = fd;
    if (data)
        ev.data.ptr = data;
    ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;

    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        perror("epoll_ctl(2): add epollin");
    }
}


void mod_epoll(const int efd, const int fd, const int evs, void *data) {
    struct epoll_event ev;
    ev.data.fd = fd;
    if (data)
        ev.data.ptr = data;
    ev.events = evs | EPOLLET | EPOLLONESHOT;

    if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev) < 0) {
        perror("epoll_ctl(2): set epollout");
    }
}


void del_epoll(const int efd, const int fd) {
    if (epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL) < 0)
        perror("epoll_ctl(2): set epollout");
}


/* Host-to-network (native endian to big endian) */
void htonll(uint8_t *block, uint_least64_t num) {
    block[0]=num>>56&0xFF;
    block[1]=num>>48&0xFF;
    block[2]=num>>40&0xFF;
    block[3]=num>>32&0xFF;
    block[4]=num>>24&0xFF;
    block[5]=num>>16&0xFF;
    block[6]=num>>8&0xFF;
    block[7]=num>>0&0xFF;
}

/* Network-to-host (big endian to native endian) */
uint_least64_t ntohll(const uint8_t *block) {
    return (uint_least64_t)block[0]<<56|
        (uint_least64_t)block[1]<<48|
        (uint_least64_t)block[2]<<40|
        (uint_least64_t)block[3]<<32|
        (uint_least64_t)block[4]<<24|
        (uint_least64_t)block[5]<<16|
        (uint_least64_t)block[6]<<8|
        (uint_least64_t)block[7]<<0;
}
