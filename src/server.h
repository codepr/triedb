/* BSD 2-Clause License
 *
 * Copyright (c) 2018, 2019, Andrea Giacomo Baldan All rights reserved.
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

#include "db.h"
#include "pack.h"
#include "trie.h"
#include "list.h"
#include "vector.h"
#include "cluster.h"
#include "protocol.h"
#include "hashtable.h"

/*
 * Epoll default settings for concurrent events monitored and timeout, -1
 * means no timeout at all, blocking undefinitely
 */
#define EPOLL_MAX_EVENTS    256
#define EPOLL_TIMEOUT       -1

/* Error codes for packet reception, signaling respectively
 * - client disconnection
 * - error reading packet
 * - error packet sent exceeds size defined by configuration (generally default
 *   to 2MB)
 */
#define ERRCLIENTDC         1
#define ERRPACKETERR        2
#define ERRMAXREQSIZE       3

/* Return code of handler functions, signaling if there's data payload to be
 * sent out or if the server just need to re-arm closure for reading incoming
 * bytes
 */
#define REARM_R             0
#define REARM_W             1


#define TTL_CHECK_INTERVAL      50 * 1024 * 1024
#define STATS_PRINT_INTERVAL    15

/*
 * Number of I/O workers to start, in other words the size of the IO thread
 * pool
 */
#define IOPOOLSIZE 1

/* Number of Worker threads, or the size of the worker pool */
#define WORKERPOOLSIZE 2

/*
 * Global db instance, containing some connection data, clients, expiring keys
 * and databases
 */
struct triedb {
    /* Main epoll loop fd */
    int epollfd;
    /* Connected clients */
    HashTable *clients;
    /* Expiring keys */
    Vector *expiring_keys;
    /* struct database mappings name -> db object */
    HashTable *dbs;
    /* Total count of the database keys */
    size_t keyspace_size;
};


/*
 * Basic client structure, represents a connected client, with his last reply
 * and the command packet associated (PUT, GET, DEL etc...). It uses a function
 * pointer to define a context handler, modifying a unified interface of
 * handling based upon 3 common actions:
 *
 *    - accept
 *    - request
 *    - reply
 *
 * Each of these function is represented by a handler function in the form of
 * x_handler(struct triedb *, struct client *) where x is one of those actions.
 *
 * This way it's easier to plug-in different handlers and use epoll_wait just
 * to call the correct context.
 */

struct client {
    int fd;
    uint64_t last_action_time;
    const char uuid[37];
    struct database *db;
};


/*
 * Structure to represent a key with a TTL set which is not -NOTTL, e.g. has a
 * timeout after which the key will be deleted
 */
struct expiring_key {
    Trie *data_ptr;
    const struct db_item *item;
    const char *key;
};

/* Global informations statistics structure */
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
    /* Total number of bytes received */
    uint64_t bytes_recv;
    /* Total number of bytes sent out */
    uint64_t bytes_sent;
    /* Total number of keys stored */
    uint64_t nkeys;
};


int start_server(const char *, const char *);

ssize_t recv_packet(int, unsigned char **, unsigned char *);

#endif
