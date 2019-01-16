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

#ifndef SERVER_H
#define SERVER_H

#include "trie.h"
#include "list.h"
#include "vector.h"
#include "protocol.h"
#include "hashtable.h"


#define MAX_EVENTS	            255
#define TTL_CHECK_INTERVAL      50 * 1024 * 1024
#define STATS_PRINT_INTERVAL    15

/* Error codes help */
#define ERRMAXREQSIZE           1
#define ERRCLIENTDC             2


enum client_type { CLIENT, SERVER, NODE };

/* Global db instance, containing some connection data, clients, expiring keys
   and databases */
struct tritedb {
    /* Main epoll loop fd */
    int epollfd;
    /* Bus port for cluster communication */
    char busport[5];
    /* Connected clients */
    HashTable *clients;
    /* Other tritedb nodes connected, only in CLUSTER mode */
    HashTable *nodes;
    /* Expiring keys */
    Vector *expiring_keys;
    /* struct database mappings name -> db object */
    HashTable *dbs;
    /* Total count of the database keys */
    size_t keyspace_size;
};


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
 * x_handler(struct tritedb *, struct client *) where x is one of those actions.
 *
 * This way it's easier to plug-in different handlers and use epoll_wait just
 * to call the correct context.
 */

struct client {
    enum client_type ctype;
    uint64_t last_action_time;
    const char *addr;
    const char uuid[37];
    int fd;
    int (*ctx_handler)(struct client *);
    struct reply *reply;
    struct request *request;
    struct database *db;
};


/* Structure to represent a key with a TTL set which is not -NOTTL, e.g. has a
   timeout after which the key will be deleted */
struct expiring_key {
    Trie *data_ptr;
    const struct node_data *nd;
    const char *key;
};


/* Simple database abstraction, provide some namespacing to keyspace for each
   client */
struct database {
    const char *name;
    Trie *data;
};


struct informations {
    /* Number of clients currently connected */
    uint32_t nclients;
    /* Number of nodes currently connected */
    uint16_t nnodes;
    /* Total number of clients connected since the start */
    uint32_t nconnections;
    /* Timestamp of the start time */
    uint64_t start_time;
    /* Seconds passed since the start */
    uint64_t uptime;
    /* Total number of requests served */
    uint32_t nrequests;
    /* Total number of bytes received */
    uint64_t ninputbytes;
    /* Total number of bytes sent out */
    uint64_t noutputbytes;
};


int start_server(const char *, const char *, int);


#endif
