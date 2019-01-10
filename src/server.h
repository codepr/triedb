/* BSD 2-Clause License
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

#ifndef SERVER_H
#define SERVER_H

#include "trie.h"
#include "list.h"
#include "vector.h"
#include "protocol.h"
#include "hashtable.h"


#define MAX_EVENTS	            128
#define TTL_CHECK_INTERVAL      50 * 1024 * 1024
#define STATS_PRINT_INTERVAL    15

/* Error codes help */
#define ERRMAXREQSIZE           1
#define ERRCLIENTDC             2


typedef struct client Client;

typedef struct reply Reply;

typedef struct tritedb TriteDB;


/* Basic client structure, represents a connected client, with his last reply
 * and the command packet associated (PUT, GET, DEL etc...). It uses a function
 * pointer to define a context handler, modifying a unified interface of
 * handling based upon 3 common actions:
 *
 *    - accept
 *    - request
 *    - reply
 *
 * Each of these function is represented by a handler function in the form of
 * x_handler(TriteDB *, Client *) where x is one of those actions.
 *
 * This way it's easier to plug-in different handlers and use epoll_wait just
 * to call the correct context.
 */

struct client {
    uint64_t last_action_time;
    const char *addr;
    const char uuid[37];
    int fd;
    int (*ctx_handler)(TriteDB *, Client *);
    Reply *reply;
    void *ptr;
};


struct reply {
    int fd;
    Buffer *payload;
};


struct command {
    int ctype;
    int (*handler)(TriteDB *, Client *);
};


struct ExpiringKey {
    const struct NodeData *nd;
    const char *key;
};


struct tritedb {
    /* Main epoll loop fd */
    int epollfd;
    /* Main object map */
    Trie *data;
    /* Connected clients */
    HashTable *clients;
    /* Peers connected */
    List *peers;
    /* Expiring keys */
    Vector *expiring_keys;
};


struct informations {
    /* Number of clients currently connected */
    uint32_t nclients;
    /* Total number of clients connected since the start */
    uint32_t nconnections;
    /* Timestamp of the start time */
    uint64_t start_time;
    /* Seconds passed since the start */
    uint64_t uptime;
    /* Total number of requests served */
    uint32_t nrequests;
};


extern struct informations info;


int start_server(const char *, const char *, int );


#endif
