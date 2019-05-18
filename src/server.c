/* BSD 2-Clause License
 *
 * Copyright (c) 2018, 2019 Andrea Giacomo Baldan All rights reserved.
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

#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <uuid/uuid.h>
#include "list.h"
#include "pack.h"
#include "util.h"
#include "server.h"
#include "config.h"
#include "network.h"
#include "protocol.h"


static pthread_spinlock_t spinlock;


struct io_event {
    int epollfd;
    eventfd_t io_event;
    struct client *client;
    bstring reply;
    union triedb_request *payload;
};

/* Global information structure */
static struct informations info;

/* The main triedb instance */
static struct triedb triedb;

#define IO_WORKERS 1

#define WORKERS 2

struct epoll {
    int io_epollfd;
    int w_epollfd;
    int serverfd;
};

/* Prototype for a command handler */
typedef int handler(struct io_event *);

/* Command handler, each one have responsibility over a defined command packet */
static int put_handler(struct io_event *);

static int get_handler(struct io_event *);

static int del_handler(struct io_event *);

static int ttl_handler(struct io_event *);

static int inc_handler(struct io_event *);

static int dec_handler(struct io_event *);

static int cnt_handler(struct io_event *);

static int use_handler(struct io_event *);

static int keys_handler(struct io_event *);

static int ping_handler(struct io_event *);

static int quit_handler(struct io_event *);

/* Command handler mapped usign their position paired with their type */
static handler *handlers[12] = {
    NULL,
    put_handler,
    get_handler,
    del_handler,
    ttl_handler,
    inc_handler,
    dec_handler,
    cnt_handler,
    use_handler,
    keys_handler,
    ping_handler,
    quit_handler
};


static bstring ack_replies[3];


static int put_handler(struct io_event *event) {

    union triedb_request *packet = event->payload;
    struct client *c = event->client;

#if WORKERS > 1
    pthread_spin_lock(&spinlock);
#endif

    if (packet->header.bits.prefix == 1) {
        database_prefix_set(c->db, (const char *) packet->put.key,
                            packet->put.val, packet->put.ttl);
    } else {
        database_insert(c->db, (const char *) packet->put.key,
                        packet->put.val, packet->put.ttl);
        // Update total counter of keys
        triedb.keyspace_size++;
    }

#if WORKERS > 1
    pthread_spin_unlock(&spinlock);
#endif
    event->reply = ack_replies[OK];

    return 0;
}


static int get_handler(struct io_event *event) {

    union triedb_request *packet = event->payload;
    struct client *c = event->client;

    void *val = NULL;

#if WORKERS > 1
    pthread_spin_lock(&spinlock);
#endif
    // Test for the presence of the key in the trie structure
    bool found = database_search(c->db, (const char *) packet->get.key, &val);
#if WORKERS > 1
    pthread_spin_unlock(&spinlock);
#endif

    if (found == false || val == NULL)
        goto nok;

    event->reply = bstring_new(((struct db_item *) val)->data);

    return 0;

nok:

    event->reply = ack_replies[NOK];

    return 0;

}


static int del_handler(struct io_event *event) {

    union triedb_request *packet = event->payload;
    struct client *c = event->client;

    size_t currsize = 0;

    /*
     * For each key in the keys array, check for presence and try to remove it,
     * if the `is_prefix` flag is a set the key will be treated as a prefix
     * wildcard (*) and we'll remove all keys below it in the trie
     */
    if (packet->get.header.bits.prefix == 1) {

        currsize = database_size(c->db);

#if WORKERS > 1
        pthread_spin_lock(&spinlock);
#endif
        /*
         * We are dealing with a wildcard, so we apply the deletion
         * to all keys below the wildcard
         */
        /* database_prefix_remove(c->db, (const char *) packet->get.key); */
#if WORKERS > 1
        pthread_spin_unlock(&spinlock);
#endif

        // Update total keyspace counter
        triedb.keyspace_size -= currsize - database_size(c->db);

        event->reply = ack_replies[OK];

    } else {
#if WORKERS > 1
        pthread_spin_lock(&spinlock);
#endif
        bool found = database_remove(c->db, (const char *) packet->get.key);
#if WORKERS > 1
        pthread_spin_unlock(&spinlock);
#endif
        if (found == false)
            event->reply = ack_replies[NOK];
        else {
            // Update total keyspace counter
            triedb.keyspace_size--;
            event->reply = ack_replies[OK];
        }
    }

    return 0;
}


static bool compare_ttl(void *arg1, void *arg2) {

    time_t now = time(NULL);

    /* cast to cluster_node */
    const struct db_item *n1 = ((struct expiring_key *) arg1)->item;
    const struct db_item *n2 = ((struct expiring_key *) arg2)->item;

    time_t delta_l1 = (n1->ctime + n1->ttl) - now;
    time_t delta_l2 = (n2->ctime + n2->ttl) - now;

    return delta_l1 <= delta_l2;
}


static int ttl_handler(struct io_event *event) {

    union triedb_request *packet = event->payload;
    struct client *c = event->client;
    void *val = NULL;

    // Check for key presence in the trie structure
    bool found = trie_find(c->db->data, (const char *) packet->ttl.key, &val);

    if (found == false || val == NULL) {
        event->reply = ack_replies[NOK];
    } else {
        struct db_item *item = val;
        bool has_ttl = !(item->ttl < 0);
        item->ttl = packet->ttl.ttl;

        /*
         * It's a new TTL, so we update creation_time to now in order to
         * calculate the effective expiration of the key
         */
        item->ctime = item->lstime = time(NULL);
        struct expiring_key *ek = tmalloc(sizeof(*ek));
        ek->item = item;
        ek->key = tstrdup((const char *) packet->ttl.key);
        ek->data_ptr = c->db->data;

        /*
         * Push into the expiring keys list and merge sort it shortly after,
         * this way we have a mostly updated list of expiring keys at each
         * insert, making it simpler and more efficient to cycle through them
         * and remove it later.
         */
        if (!has_ttl)
            vector_append(triedb.expiring_keys, ek);

        vector_qsort(triedb.expiring_keys,
                     compare_ttl, sizeof(struct expiring_key));

        event->reply = ack_replies[OK];
    }

    return 0;
}


static int inc_handler(struct io_event *event) {

    union triedb_request *packet = event->payload;
    struct client *c = event->client;

    if (packet->incr.header.bits.prefix == 1) {
        database_prefix_inc(c->db, (const char *) packet->incr.key);
    } else {

        bool found = false;
        void *val = NULL;

        /* check for presence and increment it by one */
        found = database_search(c->db, (const char *) packet->incr.key, &val);

        if (found == false || !val) {
            event->reply = ack_replies[NOK];
        } else {

            struct db_item *item = val;

            if (!is_integer(item->data))
                event->reply = ack_replies[NOK];
            else
                item->data = update_integer_string(item->data, 1);
        }
    }

    return 0;
}


static int dec_handler(struct io_event *event) {

    union triedb_request *packet = event->payload;
    struct client *c = event->client;

    if (packet->incr.header.bits.prefix == 1) {
        database_prefix_dec(c->db, (const char *) packet->incr.key);
    } else {

        bool found = false;
        void *val = NULL;

        /* check for presence and increment it by one */
        found = database_search(c->db, (const char *) packet->incr.key, &val);

        if (found == false || !val) {
            event->reply = ack_replies[NOK];
        } else {

            struct db_item *item = val;

            if (!is_integer(item->data))
                event->reply = ack_replies[NOK];
            else
                item->data = update_integer_string(item->data, -1);
        }
    }

    return 0;
}


static int cnt_handler(struct io_event *event) {

    unsigned long long count = 0;
    union triedb_request *packet = event->payload;
    struct client *c = event->client;

    /*
     * Prefix operation by default, get the size of each key below the
     * requested one, glob operation or the entire trie size in case of NULL
     * key
     */
    count = !packet->count.key ? database_size(c->db) :
        database_prefix_count(c->db, (const char *) packet->count.key);

    event->reply = pack_cnt(CNT, count);

    return 0;
}


static int use_handler(struct io_event *event) {

    union triedb_request *packet = event->payload;
    struct client *c = event->client;

    /* Check for presence first */
    struct database *database =
        hashtable_get(triedb.dbs, (const char *) packet->usec.key);

    /*
     * It doesn't exist, we create a new database with the given name,
     * otherwise just assign it to the current db of the client
     */
    if (!database) {
        // TODO check for OOM
        database = tmalloc(sizeof(*database));
        database_init(database, tstrdup((const char *) packet->usec.key), NULL);

        // Add it to the databases table
        hashtable_put(triedb.dbs, tstrdup(database->name), database);
        c->db = database;
    } else {
        c->db = database;
    }

    return 0;
}


static int keys_handler(struct io_event *event) {
    return 0;
}


static int ping_handler(struct io_event *event) {
    return 0;
}


static int quit_handler(struct io_event *event) {
    return 0;
}


#define EPOLL_ERR(ev) if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP) || \
                          (!(ev.events & EPOLLIN) && !(ev.events & EPOLLOUT)))


static void accept_loop(struct epoll *epoll) {

    int events = 0;

    struct epoll_event *e_events =
        tmalloc(sizeof(struct epoll_event) * EPOLL_MAX_EVENTS);

    int epollfd = epoll_create1(0);

    epoll_add(epollfd, epoll->serverfd, EPOLLIN, NULL);
    epoll_add(epollfd, conf->run, EPOLLIN, NULL);

    while (1) {

        events = epoll_wait(epollfd, e_events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT);

        if (events < 0) {

            /* Signals to all threads. Ignore it for now */
            if (errno == EINTR)
                continue;

            /* Error occured, break the loop */
            break;
        }

        for (int i = 0; i < events; i++) {

            /* Check for errors */
            EPOLL_ERR(e_events[i]) {

                /* An error has occured on this fd, or the socket is not
                   ready for reading, closing connection */
                perror ("epoll_wait(2)");
                close(e_events[i].data.fd);

            } else if (e_events[i].data.fd == conf->run) {

                /* And quit event after that */
                eventfd_t val;
                eventfd_read(conf->run, &val);

                tdebug("Stopping epoll loop. Thread %p exiting.",
                       (void *) pthread_self());

                goto exit;
            } else if (e_events[i].data.fd == epoll->serverfd) {

                while (1) {

                    int fd = accept_connection(epoll->serverfd);
                    if (fd < 0)
                        break;

                    /* Create a client structure to handle his context connection */
                    struct client *client = tmalloc(sizeof(struct client));
                    if (!client)
                        oom("creating client during accept");

                    /* Generate random uuid */
                    uuid_t binuuid;
                    uuid_generate_random(binuuid);
                    uuid_unparse(binuuid, (char *) client->uuid);

                    /* Populate client structure */
                    client->fd = fd;

                    /* Record last action as of now */
                    client->last_action_time = (uint64_t) time(NULL);

                    /* Set the default db for the current user */
                    client->db = hashtable_get(triedb.dbs, "db0");

                    /* Add it to the db instance */
                    hashtable_put(triedb.clients, client->uuid, client);

                    /* Add it to the epoll loop */
                    epoll_add(epoll->io_epollfd, fd, EPOLLIN, client);

                    /* Rearm server fd to accept new connections */
                    epoll_mod(epollfd, epoll->serverfd, EPOLLIN, NULL);

                    /* Record the new client connected */
                    info.nclients++;
                    info.nconnections++;

                }
            }
        }
    }

exit:

    tfree(e_events);
}

/* Handle incoming requests, after being accepted or after a reply */
static int read_data(int fd, unsigned char *buffer, union triedb_request *pkt) {

    ssize_t bytes = 0;
    unsigned char header = 0;

    /*
     * We must read all incoming bytes till an entire packet is received. This
     * is achieved by following the MQTT v3.1.1 protocol specifications, which
     * send the size of the remaining packet as the second byte. By knowing it
     * we know if the packet is ready to be deserialized and used.
     */
    bytes = recv_packet(fd, &buffer, &header);

    /*
     * Looks like we got a client disconnection.
     *
     * TODO: Set a error_handler for ERRMAXREQSIZE instead of dropping client
     *       connection, explicitly returning an informative error code to the
     *       client connected.
     */
    if (bytes == -ERRCLIENTDC || bytes == -ERRMAXREQSIZE)
        goto errdc;

    /*
     * If a not correct packet received, we must free the buffer and reset the
     * handler to the request again, setting EPOLL to EPOLLIN
     */
    if (bytes == -ERRPACKETERR)
        goto exit;

    info.bytes_recv += bytes;

    /*
     * Unpack received bytes into a triedb_request structure and execute the
     * correct handler based on the type of the operation.
     */
    unpack_triedb_request(buffer, pkt, header, bytes);

    return 0;

exit:

    return -ERRPACKETERR;

errdc:

    terror("Dropping client");
    close(fd);

    info.nclients--;

    info.nconnections--;

    return -ERRCLIENTDC;
}


static void *io_worker(void *arg) {

    struct epoll *epoll = arg;
    int events = 0;

    struct epoll_event *e_events =
        tmalloc(sizeof(struct epoll_event) * EPOLL_MAX_EVENTS);

    /* Raw bytes buffer to handle input from client */
    unsigned char *buffer = tmalloc(conf->max_request_size);

    while (1) {

        events = epoll_wait(epoll->io_epollfd, e_events,
                            EPOLL_MAX_EVENTS, EPOLL_TIMEOUT);

        if (events < 0) {

            /* Signals to all threads. Ignore it for now */
            if (errno == EINTR)
                continue;

            /* Error occured, break the loop */
            break;
        }

        for (int i = 0; i < events; i++) {

            /* Check for errors */
            EPOLL_ERR(e_events[i]) {

                /* An error has occured on this fd, or the socket is not
                   ready for reading, closing connection */
                perror ("epoll_wait(2)");
                close(e_events[i].data.fd);

            } else if (e_events[i].data.fd == conf->run) {

                /* And quit event after that */
                eventfd_t val;
                eventfd_read(conf->run, &val);

                tdebug("Stopping epoll loop. Thread %p exiting.",
                       (void *) pthread_self());

                goto exit;

            } else if (e_events[i].events & EPOLLIN) {
                struct io_event *event = tmalloc(sizeof(*event));
                event->epollfd = epoll->io_epollfd;
                event->payload = tmalloc(sizeof(*event->payload));
                event->client = e_events[i].data.ptr;
                int rc = read_data(event->client->fd, buffer, event->payload);
                if (rc == 0) {
                    eventfd_t ev = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
                    event->io_event = ev;
                    epoll_add(epoll->w_epollfd, ev, EPOLLIN, event);
                    eventfd_write(ev, 1);
                }
                else if (rc == -ERRCLIENTDC)
                    close(event->client->fd);
            } else if (e_events[i].events & EPOLLOUT) {
                struct io_event *event = e_events[i].data.ptr;
                if (send_bytes(event->client->fd,
                               (const unsigned char *) event->reply,
                               bstring_len(event->reply)) < 0) {
                    close(event->client->fd);
                }
                epoll_mod(epoll->io_epollfd, event->client->fd, EPOLLIN, event->client);
                bstring_destroy(event->reply);
            }
        }
    }

exit:

    tfree(e_events);
    tfree(buffer);

    return NULL;
}


static void *worker(void *arg) {

    struct epoll *epoll = arg;
    int events = 0;
    eventfd_t val;

    struct epoll_event *e_events =
        tmalloc(sizeof(struct epoll_event) * EPOLL_MAX_EVENTS);

    while (1) {

        events = epoll_wait(epoll->w_epollfd, e_events,
                            EPOLL_MAX_EVENTS, EPOLL_TIMEOUT);

        if (events < 0) {

            /* Signals to all threads. Ignore it for now */
            if (errno == EINTR)
                continue;

            /* Error occured, break the loop */
            break;
        }

        for (int i = 0; i < events; i++) {

            /* Check for errors */
            EPOLL_ERR(e_events[i]) {

                /* An error has occured on this fd, or the socket is not
                   ready for reading, closing connection */
                perror ("epoll_wait(2)");
                close(e_events[i].data.fd);

            } else if (e_events[i].data.fd == conf->run) {

                /* And quit event after that */
                eventfd_read(conf->run, &val);

                tdebug("Stopping epoll loop. Thread %p exiting.",
                       (void *) pthread_self());

                goto exit;

            } else if (e_events[i].events & EPOLLIN) {
                struct io_event *event = e_events[i].data.ptr;
                handlers[event->payload->header.bits.opcode](event);
                epoll_mod(event->epollfd, event->client->fd, EPOLLOUT, event);
                close(event->io_event);
                triedb_request_destroy(event->payload);
            }
        }
    }

exit:

    tfree(e_events);

    return NULL;
}

/*
 * Parse packet header, it is required at least the Fixed Header of each
 * packed, which is contained in the first 2 bytes in order to read packet
 * type and total length that we need to recv to complete the packet.
 *
 * This function accept a socket fd, a buffer to read incoming streams of
 * bytes and a structure formed by 2 fields:
 *
 * - buf -> a byte buffer, it will be malloc'ed in the function and it will
 *          contain the serialized bytes of the incoming packet
 * - flags -> flags pointer, copy the flag setting of the incoming packet,
 *            again for simplicity and convenience of the caller.
 */
ssize_t recv_packet(int clientfd, unsigned char **buf, unsigned char *header) {

    ssize_t nbytes = 0;
    unsigned char *tmpbuf = *buf;

    /* Read the first byte, it should contain the message type code */
    if ((nbytes = recv_bytes(clientfd, *buf, 4)) <= 0)
        return -ERRCLIENTDC;

    *header = *tmpbuf;
    tmpbuf++;

    if (DEL < *header >> 4 || PUT > *header >> 4)
        return -ERRPACKETERR;

    /*
     * Read remaning length bytes which starts at byte 2 and can be long to 4
     * bytes based on the size stored, so byte 2-5 is dedicated to the packet
     * length.
     */
    int n = 0;

    unsigned pos = 0;
    unsigned long long tlen = decode_length((const unsigned char **) &tmpbuf,
                                            &pos);
    /*
     * Set return code to -ERRMAXREQSIZE in case the total packet len exceeds
     * the configuration limit `max_request_size`
     */
    if (tlen > conf->max_request_size) {
        nbytes = -ERRMAXREQSIZE;
        goto exit;
    }

    if (tlen <= 4)
        goto exit;

    /* Read remaining bytes to complete the packet */
    if ((n = recv_bytes(clientfd, tmpbuf + pos + 1, tlen - pos)) < 0)
        goto err;

    nbytes += n - pos - 1;

exit:

    *buf += pos + 1;

    return nbytes;

err:

    close(clientfd);

    return nbytes;

}


static void expire_keys(void) {

    if (vector_size(triedb.expiring_keys) == 0)
        return;

    time_t now = time(NULL);
    time_t delta = 0LL;
    struct expiring_key *ek = NULL;

    for (int i = 0; i < vector_size(triedb.expiring_keys); i++) {

        ek = vector_get(triedb.expiring_keys, i);
        delta = (ek->item->ctime + ek->item->ttl) - now;

        if (delta > 0)
            break;

        /*
         * ek->data_ptr points to the trie of the client which stores the given
         * key
         */
        trie_delete(ek->data_ptr, ek->key);

        vector_delete(triedb.expiring_keys, i);

        // Update total keyspace counter
        triedb.keyspace_size--;

        tdebug("%s expired", ek->key);

        tfree((char *) ek->key);
        tfree(ek);
        ek = NULL;
    }
}


static inline int client_destructor(struct hashtable_entry *entry) {

    if (!entry || !entry->val)
        return -HASHTABLE_ERR;

    struct client *client = entry->val;

    tfree(client);

    return HASHTABLE_OK;
}


static inline int database_destructor(struct hashtable_entry *entry) {

    if (!entry)
        return -HASHTABLE_ERR;

    struct database *db = entry->val;

    tfree((char *) (db->name));

    trie_destroy(db->data);

    tfree(entry->val);
    tfree((char *) entry->key);

    return HASHTABLE_OK;
}


int start_server(const char *addr, const char *port) {

    for (int i = 0; i < 3; i++)
        ack_replies[i] = pack_ack(ACK, i);

#if WORKERS > 1
    pthread_spin_init(&spinlock, PTHREAD_PROCESS_SHARED);
#endif

    /* Create default database */
    struct database *default_db = tmalloc(sizeof(struct database));
    database_init(default_db, tstrdup("db0"), NULL);

    /* Initialize global triedb instance */
    triedb.dbs = hashtable_new(database_destructor);
    triedb.clients = hashtable_new(client_destructor);

    /* Add it to the global map */
    hashtable_put(triedb.dbs, tstrdup(default_db->name), default_db);

    int sfd = make_listen(addr, port, conf->socket_family);

    struct epoll epoll = {
        .io_epollfd = epoll_create1(0),
        .w_epollfd = epoll_create1(0),
        .serverfd = sfd
    };

    epoll_add(epoll.io_epollfd, conf->run, EPOLLIN, NULL);
    epoll_add(epoll.w_epollfd, conf->run, EPOLLIN, NULL);

    pthread_t iothreads[IO_WORKERS];
    pthread_t workers[WORKERS];

    for (int i = 0; i < IO_WORKERS; i++)
        pthread_create(&iothreads[i], NULL, &io_worker, &epoll);

    for (int i = 0; i < WORKERS; i++)
        pthread_create(&workers[i], NULL, &worker, &epoll);

    tinfo("Server start");
    info.start_time = time(NULL);

    // Main thread for accept new connections
    accept_loop(&epoll);

    hashtable_destroy(triedb.dbs);
    hashtable_destroy(triedb.clients);

    for (int i = 0; i < 3; i++)
        bstring_destroy(ack_replies[i]);

    tinfo("triedb v%s exiting", VERSION);

    return 0;
}

/* #<{(| Error code to separate ACK responses from ACK needed to build up a cluster |)}># */
/* static const int JUSTACK = 0x05; */
/*  */
/*  */
/* #<{(| */
/*  * Helper macro to create a join request to a defined seed node, communicating */
/*  * address and port */
/*  |)}># */
/* #define make_join_request(addr, port, flags)                            \ */
/*     make_keyval_request((const uint8_t *) addr, (const uint8_t *) port, \ */
/*                         CLUSTER_JOIN, 0x00, flags);                     \ */
/*  */
/* #<{(| */
/*  * Helper macro to set an ACK reply, just a normal reply with only a return */
/*  * code for responding to commands like PUT or DEL, stating the result of the */
/*  * operation */
/*  |)}># */
/* #define set_ack_reply(c, o, t, f) do {                                  \ */
/*     struct header hdr;                                                  \ */
/*     struct response resp = {                                            \ */
/*         .ncontent = &(struct no_content) {                              \ */
/*             .header = &hdr,                                             \ */
/*             .code = o                                                   \ */
/*         }                                                               \ */
/*     };                                                                  \ */
/*     ack_response_init(&resp, o, f, (const char *) t);                   \ */
/*     struct buffer *buffer = buffer_new(resp.ncontent->header->size); \ */
/*     pack_response(buffer, &resp);                                       \ */
/*     set_reply((c), buffer);                                             \ */
/* } while (0) */
/*
 * Reply structure, contains the file descriptor of a connected client and a
 * pointer to a buffer structure which contains the payload to be sent through
 * the socket and his length
 */
/* struct reply { */
/*     int fd; */
/*     struct buffer *payload; */
/* }; */
/*  */
/* #<{(| */
/*  * Command handler helper structure, just for mapping */
/*  * command type -> command handler functions easily */
/*  |)}># */
/* struct command_handler { */
/*     int ctype; */
/*     int (*handler)(struct client *); */
/* }; */
/*  */
/*
 * Multiple requests struct, to handle key_list requests in cluster mode, each
 * one of these structure will be a value in a key->val hashtable mapping
 * node-uuid -> multirequest.
 * It contains the transaction ID of the request, the socket descriptor of the
 * node of reference and a list of keys which will serve to construct the
 * effective key_list_request
 */
/* struct multirequest { */
/*     uint8_t opcode; */
/*     uint8_t flags; */
/*     int fd; */
/*     char transaction_id[UUID_LEN]; */
/*     List *keys; */
/* }; */

/*
 * Connection structure for private use of the module, mainly for accepting
 * new connections
 */
/* struct connection { */
/*     char ip[INET_ADDRSTRLEN + 1]; */
/*     int fd; */
/* }; */

/*
 * General context handler functions, with the exception of free_reply which
 * is just an helper function to deallocate a reply structure, all of them
 * should be associated to a requesting client on each different step of
 * execution, being them ACCEPT -> REQUST -> REPLY
 */
/* static void free_reply(struct reply *); */
/* static int accept_handler(struct client *); */
/* static int accept_node_handler(struct client *); */
/* static int read_handler(struct client *); */
/* static int write_handler(struct client *); */
/* static int route_command(struct request *, struct client *); */
/* static inline ssize_t reply_to_client(struct response *, struct buffer *); */
/* static inline ssize_t send_data(int, const uint8_t *, size_t); */
/* static inline ssize_t write_to_node(int, struct request *, size_t, uint8_t); */

/* Specific handlers for commands that every client can request */
/* static int ack_handler(struct client *); */
/* static int put_handler(struct client *); */
/* static int get_handler(struct client *); */
/* static int del_handler(struct client *); */
/* static int ttl_handler(struct client *); */
/* static int inc_handler(struct client *); */
/* static int dec_handler(struct client *); */
/* static int use_handler(struct client *); */
/* static int cluster_join_handler(struct client *); */
/* static int cluster_members_handler(struct client *); */
/* static int ping_handler(struct client *); */
/* static int db_handler(struct client *); */
/* static int count_handler(struct client *); */
/* static int keys_handler(struct client *); */
/* static int info_handler(struct client *); */
/* static int quit_handler(struct client *); */

/*
 * Fixed size of the header of each packet, consists of essentially the first
 * 5 bytes containing respectively the type of packet (PUT, GET, DEL etc ...)
 * the total length in bytes of the packet and the is_bulk flag which tell if
 * the packet contains a stream of commands or a single one
 */
/* static const int HEADLEN = (2 * sizeof(uint8_t)) + sizeof(uint32_t); */

/* Static command map, simple as it seems: OPCODE -> handler func */
/* static struct command_handler commands_map[COMMAND_COUNT] = { */
/*     {ACK, ack_handler}, */
/*     {PUT, put_handler}, */
/*     {GET, get_handler}, */
/*     {DEL, del_handler}, */
/*     {TTL, ttl_handler}, */
/*     {INC, inc_handler}, */
/*     {DEC, dec_handler}, */
/*     {COUNT, count_handler}, */
/*     {KEYS, keys_handler}, */
/*     {USE, use_handler}, */
/*     {CLUSTER_JOIN, cluster_join_handler}, */
/*     {CLUSTER_MEMBERS, cluster_members_handler}, */
/*     {PING, ping_handler}, */
/*     {DB, db_handler}, */
/*     {INFO, info_handler}, */
/*     {QUIT, quit_handler} */
/* }; */
/*
 * Given a response (buffer is just the serialized version of the response,
 * for convenience) check and try to retrieve from the global transactions map
 * if there's one pending associated with the response and forward the payload
 * of the buffer to the client associated with the transaction code.
 */
/* static ssize_t reply_to_client(struct response *response, */
/*                                struct buffer *buffer) { */
/*  */
/*     struct client *c = NULL; */
/*  */
/*     switch (response->restype) { */
/*         case NO_CONTENT: */
/*             c = hashtable_get(triedb.transactions, */
/*                               response->ncontent->header->transaction_id); */
/*             break; */
/*         case DATA_CONTENT: */
/*             c = hashtable_get(triedb.transactions, */
/*                               response->dcontent->header->transaction_id); */
/*             break; */
/*         case VALUE_CONTENT: */
/*             c = hashtable_get(triedb.transactions, */
/*                               response->vcontent->header->transaction_id); */
/*             break; */
/*         case LIST_CONTENT: */
/*             c = hashtable_get(triedb.transactions, */
/*                               response->lcontent->header->transaction_id); */
/*             break; */
/*         case KVLIST_CONTENT: */
/*             c = hashtable_get(triedb.transactions, */
/*                               response->kvlcontent->header->transaction_id); */
/*             break; */
/*     } */
/*  */
/*     #<{(| No transaction saved for the response received |)}># */
/*     if (!c) */
/*         return -1; */
/*  */
/*     #<{(| Send out data to the correct client which previous made the request |)}># */
/*     size_t sent; */
/*     if ((sendall(c->fd, buffer->data, buffer->size, &sent)) < 0) { */
/*         perror("send(2): can't write on socket descriptor"); */
/*         return -1; */
/*     } */
/*  */
/*     return sent; */
/* } */

/* Write `size` bytes on socket descriptor */
/* static inline ssize_t send_data(int fd, const uint8_t *bytes, size_t size) { */
/*     size_t sent; */
/*     if ((sendall(fd, bytes, size, &sent)) < 0) { */
/*         terror("server::send_data: %s", strerror(errno)); */
/*         return -1; */
/*     } */
/*     return sent; */
/* } */

/*
 * Write request data to the client defined by the socket descriptor `fd` by
 * creating a struct buffer of size `size` first which will contain the packed
 * response
 */
/* static inline ssize_t write_to_node(int fd, struct request *request, */
/*                                     size_t size, uint8_t reqtype) { */
/*     struct buffer *buffer = buffer_new(size); */
/*     pack_request(buffer, request, reqtype); */
/*     ssize_t bytes = send_data(fd, buffer->data, buffer->size); */
/*     buffer_destroy(buffer); */
/*     return bytes; */
/* } */

/*
 * Build a reply object and link it to the struct client pointer. Even tho it
 * removes the const qualifier from the struct buffer pointed by the ptr as a
 * matter of fact it doesn't touch it, so it is semantically correct to mark
 * it as const in the declaration.
 */
/* static inline void set_reply(struct client *client, */
/*                              const struct buffer *payload) { */
/*  */
/*     struct reply *rep = tmalloc(sizeof(*rep)); */
/*  */
/*     if (!rep) */
/*         oom("setting reply"); */
/*  */
/*     rep->fd = client->fd; */
/*     rep->payload = (struct buffer *) payload; */
/*  */
/*     client->reply = rep; */
/* } */
/*  */
/*  */
/* static inline void free_reply(struct reply *r) { */
/*  */
/*     if (!r) */
/*         return; */
/*  */
/*     if (r->payload) */
/*         buffer_destroy(r->payload); */
/*  */
/*     tfree(r); */
/* } */
/*  */
/* #<{(| List destructor function for struct keyval objects |)}># */
/* static inline int keyval_list_destroy(struct list_node *ln) { */
/*  */
/*     if (!ln) */
/*         return -1; */
/*  */
/*     if (ln->data) { */
/*         struct keyval *kv = ln->data; */
/*         tfree(kv->key); */
/*         tfree(kv->val); */
/*     } */
/*  */
/*     tfree(ln->data); */
/*     tfree(ln); */
/*  */
/*     return 1; */
/* } */
/*  */
/* #<{(| Queue destructor function for struct keyval objects. |)}># */
/* static inline int keyval_queue_destroy(struct queue_item *qitem) { */
/*  */
/*     if (!qitem) */
/*         return -1; */
/*  */
/*     keyval_queue_destroy(qitem->next); */
/*  */
/*     if (qitem->data) { */
/*         struct keyval *kv = qitem->data; */
/*         tfree(kv->key); */
/*         tfree(kv->val); */
/*     } */
/*  */
/*     tfree(qitem->data); */
/*     tfree(qitem); */
/*  */
/*     return 1; */
/* } */


/* static inline void client_destroy(struct client *client) { */
/*  */
/*     if (client->addr) */
/*         tfree((char *) client->addr); */
/*  */
/*     if (client->reply) */
/*         free_reply(client->reply); */
/*  */
/*     tfree(client); */
/* } */
/*  */
/* #<{(| Hashtable destructor function for struct client objects. |)}># */
/* static inline int hashtable_client_destroy(struct hashtable_entry *entry) { */
/*  */
/*     if (!entry || !entry->val) */
/*         return -HASHTABLE_ERR; */
/*  */
/*     struct client *c = entry->val; */
/*  */
/*     client_destroy(c); */
/*  */
/*     return HASHTABLE_OK; */
/* } */
/*  */
/* #<{(| Hashtable destructor function for transactions |)}># */
/* static inline int hashtable_transaction_destroy(struct hashtable_entry *entry) { */
/*  */
/*     if (!entry || !entry->val) */
/*         return -HASHTABLE_ERR; */
/*  */
/*     tfree((char *) entry->key); */
/*  */
/*     return HASHTABLE_OK; */
/* } */
/*  */
/* #<{(| */
/*  * Hashtable destructor function for struct database objects. It's the */
/*  * function that will be called on hashtable_del call as well as */
/*  * hashtable_release too. */
/*  |)}># */
/* static inline int database_destroy(struct hashtable_entry *entry) { */
/*  */
/*     if (!entry) */
/*         return -HASHTABLE_ERR; */
/*  */
/*     struct database *db = entry->val; */
/*  */
/*     tfree((char *) (db->name)); */
/*  */
/*     if (db->st_type == STORE_HT_TYPE) */
/*         hashtable_destroy(db->ht_data); */
/*     else */
/*         trie_destroy(db->data); */
/*  */
/*     tfree(entry->val); */
/*     tfree((char *) entry->key); */
/*  */
/*     return HASHTABLE_OK; */
/* } */
/*  */
/* #<{(| Release function for multirequest hashtable |)}># */
/* static inline int hashtable_multirequest_destroy(struct hashtable_entry *entry) { */
/*  */
/*     if (!entry || !entry->val) */
/*         return -HASHTABLE_ERR; */
/*  */
/*     struct multirequest *mrequest = entry->val; */
/*  */
/*     list_destroy(mrequest->keys, 1); */
/*  */
/*     tfree(mrequest); */
/*  */
/*     return HASHTABLE_OK; */
/* } */
/*  */
/*  */
/* #<{(|******************************|)}># */
/* #<{(|      COMMAND HANDLERS        |)}># */
/* #<{(|******************************|)}># */
/*  */
/*  */
/* static int ack_handler(struct client *c) { */
/*  */
/*     int ret = JUSTACK; */
/*  */
/*     if (!(c->response->ncontent->header->flags & */
/*           (F_FROMNODERESPONSE | F_JOINREQUEST))) */
/*         goto exit; */
/*  */
/*     #<{(| */
/*      * Check if there are pending members in queue for hash ring adding and in */
/*      * case add a connection request to the next one and add it to the ring */
/*      |)}># */
/*     if (!queue_empty(triedb.pending_members)) { */
/*  */
/*         struct keyval *pair = queue_get(triedb.pending_members); */
/*  */
/*         // Connect to the first node target */
/*         int port = atoi((const char *) pair->val) + 10000; */
/*  */
/*         int fd = open_connection((const char *) pair->key, port); */
/*  */
/*         // Create a new client for it */
/*         if (set_nonblocking(fd) < 0) */
/*             perror("set_nonblocking: "); */
/*  */
/*         if (set_tcp_nodelay(fd) < 0) */
/*             perror("set_tcp_nodelay: "); */
/*  */
/*         struct client *new_node = tmalloc(sizeof(*new_node)); */
/*         new_node->ctype = NODE; */
/*         new_node->addr = tstrdup((const char *) pair->key); */
/*         new_node->fd = fd; */
/*         new_node->last_action_time = time(NULL); */
/*         new_node->ctx_handler = read_handler; */
/*         new_node->reply = NULL; */
/*         new_node->request = NULL; */
/*         new_node->response = NULL; */
/*         new_node->db = hashtable_get(triedb.dbs, "db0"); */
/*  */
/*         generate_uuid((char *) new_node->uuid); */
/*  */
/*         if (add_epoll(triedb.epollfd, fd, EPOLLIN, new_node) < 0) */
/*             perror("epoll_add: "); */
/*  */
/*         #<{(| */
/*          * Add new node to the hashring of this instance, key field of the */
/*          * command structure should carry the host+port string joined together */
/*          |)}># */
/*         cluster_add_new_node(triedb.cluster, new_node, */
/*                              (const char *) pair->key, */
/*                              (const char *) pair->val, false); */
/*  */
/*         #<{(| Track the new connected node |)}># */
/*         hashtable_put(triedb.nodes, new_node->uuid, new_node); */
/*  */
/*         tdebug("New node on %s:%s UUID %s joined", */
/*                pair->key, pair->val, new_node->uuid); */
/*  */
/*         // Send CLUSTER_JOIN request */
/*         // XXX Obnoxious */
/*         struct request *request = make_join_request(conf->hostname, conf->port, */
/*                                                     F_FROMNODEREQUEST | */
/*                                                     F_JOINREQUEST); */
/*  */
/*         ssize_t sent; */
/*         size_t rsize = request->command->kvcommand->header->size; */
/*         if ((sent = write_to_node(new_node->fd, request, */
/*                                   rsize, KEY_VAL_COMMAND)) < 0) */
/*             terror("server::ack_handler: %s", strerror(errno)); */
/*  */
/*         free_request(request); */
/*  */
/*         // Update informations */
/*         info.nconnections++; */
/*         info.nnodes++; */
/*  */
/*         // XXX check */
/*         tfree(pair->key); */
/*         tfree(pair->val); */
/*         tfree(pair); */
/*     } */
/*  */
/* exit: */
/*  */
/*     free_response(c->response); */
/*  */
/*     return ret; */
/* } */
/*  */
/*  */
/* static int quit_handler(struct client *c) { */
/*  */
/*     tdebug("Closing connection with %s", c->addr); */
/*     del_epoll(triedb.epollfd, c->fd); */
/*     close(c->fd); */
/*     info.nclients--; */
/*  */
/*     free_request(c->request); */
/*  */
/*     // Remove client from the clients map */
/*     hashtable_del(triedb.clients, c->uuid); */
/*  */
/*     return -1; */
/* } */
/*  */
/*  */
/* static int ping_handler(struct client *c) { */
/*  */
/*     tdebug("PING from %s", c->addr); */
/*  */
/*     // TODO send out a PONG */
/*     set_ack_reply(c, OK, NULL, F_NOFLAG); */
/*  */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/*  */
/* static int info_handler(struct client *c) { */
/*  */
/*     info.uptime = time(NULL) - info.start_time; */
/*     // TODO make key-val-list response */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/*  */
/* static int keys_handler(struct client *c) { */
/*  */
/*     struct key_command *cmd = c->request->command->kcommand; */
/*  */
/*     List *keys = trie_prefix_find(c->db->data, (const char *) cmd->key); */
/*  */
/*     struct response *response = make_list_response(keys, NULL, F_NOFLAG); */
/*  */
/*     struct buffer *buffer = buffer_new(response->lcontent->header->size); */
/*     pack_response(buffer, response); */
/*  */
/*     set_reply(c, buffer); */
/*  */
/*     list_destroy(keys, 1); */
/*     free_response(response); */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/*  */
/* static bool compare_ttl(void *arg1, void *arg2) { */
/*  */
/*     uint64_t now = time(NULL); */
/*  */
/*     #<{(| cast to cluster_node |)}># */
/*     const struct node_data *n1 = ((struct expiring_key *) arg1)->item; */
/*     const struct node_data *n2 = ((struct expiring_key *) arg2)->nd; */
/*  */
/*     uint64_t delta_l1 = (n1->ctime + n1->ttl) - now; */
/*     uint64_t delta_l2 = (n2->ctime + n2->ttl) - now; */
/*  */
/*     return delta_l1 <= delta_l2; */
/* } */
/*  */
/* #<{(| */
/*  * Private function, insert or update values into the the trie database, */
/*  * updating, if any present, expiring keys vector */
/*  |)}># */
/* static void put_data_into_db(struct database *db, */
/*                              struct keyval_command *cmd) { */
/*  */
/*     int16_t ttl = cmd->ttl != 0 ? cmd->ttl : -NOTTL; */
/*  */
/*     if (db->st_type == STORE_TRIE_TYPE) { */
/*         #<{(| */
/*          * TODO refactor TTL insertion, for now it does not support expiration of */
/*          * keys below a given prefix */
/*          |)}># */
/*         if (cmd->is_prefix == 1) { */
/*             trie_prefix_set(db->data, (const char *) cmd->key, cmd->val, ttl); */
/*         } else { */
/*             struct node_data *nd = */
/*                 trie_insert(db->data, (const char *) cmd->key, cmd->val); */
/*  */
/*             bool has_ttl = nd->ttl == -NOTTL ? false : true; */
/*  */
/*             // Update expiring keys if ttl != -NOTTL and sort it */
/*             if (ttl != -NOTTL) { */
/*  */
/*                 nd->ttl = cmd->ttl; */
/*  */
/*                 #<{(| */
/*                  * It's a new TTL, so we update creation_time to now in order */
/*                  * to calculate the effective expiration of the key */
/*                  |)}># */
/*                 nd->ctime = nd->latime = (uint64_t) time(NULL); */
/*  */
/*                 // Create a data strucuture to handle expiration */
/*                 struct expiring_key *ek = tmalloc(sizeof(*ek)); */
/*                 ek->nd = nd; */
/*                 ek->key = tstrdup((const char *) cmd->key); */
/*                 ek->data_ptr = db->data; */
/*  */
/*                 #<{(| */
/*                  * Add the node data to the expiring keys only if it wasn't */
/*                  * already in, otherwise nothing should change cause the */
/*                  * expiring keys already got a pointer to the node data, which */
/*                  * will now have an updated TTL value */
/*                  |)}># */
/*                 if (!has_ttl) */
/*                     vector_append(triedb.expiring_keys, ek); */
/*  */
/*                 #<{(| */
/*                  * Quicksort in O(nlogn) if there's more than one element in */
/*                  * the vector */
/*                  |)}># */
/*                 vector_qsort(triedb.expiring_keys, */
/*                              compare_ttl, sizeof(struct expiring_key)); */
/*             } */
/*  */
/*             // Update total counter of keys */
/*             triedb.keyspace_size++; */
/*         } */
/*     } else { */
/*  */
/*         size_t ht_size = hashtable_size(db->ht_data); */
/*  */
/*         hashtable_put(db->ht_data, */
/*                       tstrdup((char *) cmd->key), tstrdup((char *) cmd->val)); */
/*  */
/*         if (hashtable_size(db->ht_data) > ht_size) */
/*             triedb.keyspace_size++; */
/*  */
/*         // TODO expiring keys support */
/*     } */
/* } */
/*  */
/*  */
/* static int put_handler(struct client *c) { */
/*  */
/*     struct request *request = c->request; */
/*     int flags = 0; */
/*     // Transaction id placeholder */
/*     char *tid = NULL; */
/*  */
/*     if (request->reqtype == SINGLE_REQUEST) { */
/*  */
/*         struct keyval_command *cmd = request->command->kvcommand; */
/*  */
/*         flags = cmd->header->flags; */
/*  */
/*         if (flags & F_FROMNODEREQUEST) */
/*             tid = cmd->header->transaction_id; */
/*  */
/*         // Insert data into the trie */
/*         put_data_into_db(c->db, cmd); */
/*  */
/*     } else { */
/*  */
/*         struct bulk_command *bcmd = request->bulk_command; */
/*  */
/*         // TODO check */
/*         flags = bcmd->commands[0]->kvcommand->header->flags; */
/*  */
/*         if (flags & F_FROMNODEREQUEST) */
/*             tid = bcmd->commands[0]->kvcommand->header->transaction_id; */
/*  */
/*         // Apply insertion for each command */
/*         for (uint32_t i = 0; i < bcmd->ncommands; i++) */
/*             put_data_into_db(c->db, bcmd->commands[i]->kvcommand); */
/*     } */
/*  */
/*     // For now just a single response */
/*     set_ack_reply(c, OK, (const uint8_t *) tid, flags & F_FROMNODEREQUEST ? */
/*                   F_FROMNODERESPONSE | F_FROMNODEREPLY : F_NOFLAG); */
/*  */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/*  */
/* static int get_handler(struct client *c) { */
/*  */
/*     struct key_command *cmd = c->request->command->kcommand; */
/*     void *val = NULL; */
/*     int flags = cmd->header->flags & F_FROMNODEREQUEST ? */
/*         F_FROMNODERESPONSE | F_FROMNODEREPLY : F_NOFLAG; */
/*  */
/*     char *tid = cmd->header->flags & F_FROMNODEREQUEST ? */
/*         cmd->header->transaction_id : NULL; */
/*  */
/*     if (c->db->st_type == STORE_TRIE_TYPE) { */
/*  */
/*         // Test for the presence of the key in the trie structure */
/*         bool found = trie_find(c->db->data, (const char *) cmd->key, &val); */
/*  */
/*         if (found == false || val == NULL) */
/*             goto setnok; */
/*  */
/*         struct node_data *nd = val; */
/*  */
/*         // If the key results expired, remove it instead of returning it */
/*         int64_t now = time(NULL); */
/*         int64_t delta = (nd->ctime + nd->ttl) - now; */
/*  */
/*         if (nd->ttl != -NOTTL && delta <= 0) { */
/*  */
/*             #<{(| Delete from the trie |)}># */
/*             trie_delete(c->db->data, (const char *) cmd->key); */
/*  */
/*             #<{(| Find index of the key in the expiring_keys vector |)}># */
/*             for (size_t i = 0; i < vector_size(triedb.expiring_keys); i++) { */
/*                 struct expiring_key *ek = vector_get(triedb.expiring_keys, i); */
/*                 if (ek->nd == nd) { */
/*                     vector_delete(triedb.expiring_keys, i); */
/*                     tfree((char *) ek->key); */
/*                     tfree(ek); */
/*                     break; */
/*                 } */
/*             } */
/*  */
/*             set_ack_reply(c, NOK, (const uint8_t *) tid, flags); */
/*  */
/*             // Update total keyspace counter */
/*             triedb.keyspace_size--; */
/*  */
/*         } else { */
/*  */
/*             // Update the last access time */
/*             nd->latime = time(NULL); */
/*  */
/*             // and return it */
/*             struct response *response = */
/*                 make_data_response(nd->data, (const uint8_t *) tid, flags); */
/*  */
/*             struct buffer *buffer = */
/*                 buffer_new(response->dcontent->header->size); */
/*  */
/*             pack_response(buffer, response); */
/*  */
/*             set_reply(c, buffer); */
/*             free_response(response); */
/*         } */
/*  */
/*     } else { */
/*  */
/*         // TODO add expiring key support */
/*  */
/*         void *data = hashtable_get(c->db->ht_data, (const char *) cmd->key); */
/*  */
/*         if (!data) */
/*             goto setnok; */
/*  */
/*         // and return it */
/*         struct response *response = */
/*             make_data_response(data, (const uint8_t *) tid, flags); */
/*  */
/*         struct buffer *buffer = */
/*             buffer_new(response->dcontent->header->size); */
/*  */
/*         pack_response(buffer, response); */
/*  */
/*         set_reply(c, buffer); */
/*         free_response(response); */
/*     } */
/*  */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/*  */
/* setnok: */
/*  */
/*     free_request(c->request); */
/*     set_ack_reply(c, NOK, (const uint8_t *) tid, flags); */
/*  */
/*     return OK; */
/* } */
/*  */
/*  */
/* static int ttl_handler(struct client *c) { */
/*  */
/*     struct key_command *cmd = c->request->command->kcommand; */
/*     void *val = NULL; */
/*  */
/*     int flags = cmd->header->flags & F_FROMNODEREQUEST ? */
/*         F_FROMNODERESPONSE | F_FROMNODEREPLY : F_NOFLAG; */
/*  */
/*     char *tid = cmd->header->flags & F_FROMNODEREQUEST ? */
/*         cmd->header->transaction_id : NULL; */
/*  */
/*     // Check for key presence in the trie structure */
/*     bool found = trie_find(c->db->data, (const char *) cmd->key, &val); */
/*  */
/*     if (found == false || val == NULL) { */
/*         set_ack_reply(c, NOK, (const uint8_t *) tid, flags); */
/*     } else { */
/*         struct node_data *nd = val; */
/*         bool has_ttl = !(nd->ttl == -NOTTL); */
/*         nd->ttl = cmd->ttl; */
/*  */
/*         #<{(| */
/*          * It's a new TTL, so we update creation_time to now in order to */
/*          * calculate the effective expiration of the key */
/*          |)}># */
/*         nd->ctime = nd->latime = (uint64_t) time(NULL); */
/*         struct expiring_key *ek = tmalloc(sizeof(*ek)); */
/*         ek->nd = nd; */
/*         ek->key = tstrdup((const char *) cmd->key); */
/*         ek->data_ptr = c->db->data; */
/*  */
/*         #<{(| */
/*          * Push into the expiring keys list and merge sort it shortly after, */
/*          * this way we have a mostly updated list of expiring keys at each */
/*          * insert, making it simpler and more efficient to cycle through them */
/*          * and remove it later. */
/*          |)}># */
/*         if (!has_ttl) */
/*             vector_append(triedb.expiring_keys, ek); */
/*  */
/*         vector_qsort(triedb.expiring_keys, */
/*                      compare_ttl, sizeof(struct expiring_key)); */
/*  */
/*         set_ack_reply(c, OK, (const uint8_t *) tid, flags); */
/*     } */
/*  */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/*  */
/* static int del_handler(struct client *c) { */
/*  */
/*     int code = OK; */
/*     struct key_list_command *cmd = c->request->command->klcommand; */
/*     bool found = false; */
/*     int flags = cmd->header->flags & F_FROMNODEREQUEST ? */
/*         F_FROMNODERESPONSE | F_FROMNODEREPLY : F_NOFLAG; */
/*  */
/*     char *tid = flags & F_FROMNODEREQUEST ? */
/*         cmd->header->transaction_id : NULL; */
/*  */
/*     if (c->db->st_type == STORE_TRIE_TYPE) { */
/*         // Flush all data in case of no prefixes passed */
/*         if (cmd->len == 0) { */
/*             trie_node_destroy(c->db->data->root, &c->db->data->size); */
/*             // Update total keyspace counter */
/*             triedb.keyspace_size = 0; */
/*         } else { */
/*             size_t currsize = 0; */
/*             for (int i = 0; i < cmd->len; i++) { */
/*  */
/*                 #<{(| */
/*                  * For each key in the keys array, check for presence and try */
/*                  * to remove it, if the `is_prefix` flag is a set the key will */
/*                  * be treated as a prefix wildcard (*) and we'll remove all */
/*                  * keys below it in the trie */
/*                  |)}># */
/*                 if (cmd->keys[i]->is_prefix == 1) { */
/*  */
/*                     currsize = c->db->data->size; */
/*  */
/*                     #<{(| */
/*                      * We are dealing with a wildcard, so we apply the deletion */
/*                      * to all keys below the wildcard */
/*                      |)}># */
/*                     trie_prefix_delete(c->db->data, */
/*                                        (const char *) cmd->keys[i]->key); */
/*  */
/*                     // Update total keyspace counter */
/*                     triedb.keyspace_size -= currsize - c->db->data->size; */
/*                 } else { */
/*                     found = trie_delete(c->db->data, */
/*                                         (const char *) cmd->keys[i]->key); */
/*                     if (found == false) */
/*                         code = NOK; */
/*                     else */
/*                         // Update total keyspace counter */
/*                         triedb.keyspace_size--; */
/*                 } */
/*             } */
/*         } */
/*     } else { */
/*  */
/*         int err; */
/*  */
/*         if (cmd->len == 0) { */
/*             hashtable_destroy(c->db->ht_data); */
/*             triedb.keyspace_size = 0; */
/*         } else { */
/*             for (int i = 0; i < cmd->len; i++) { */
/*                 err = hashtable_del(c->db->ht_data, */
/*                                     (const char *) cmd->keys[i]->key); */
/*                 if (err == -HASHTABLE_ERR) */
/*                     code = NOK; */
/*                 else */
/*                     triedb.keyspace_size--; */
/*             } */
/*         } */
/*     } */
/*  */
/*     set_ack_reply(c, code, (const uint8_t *) tid, flags); */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/* #<{(| */
/*  * Increment an integer value by 1. If the string value doesn't contain a */
/*  * proper integer return a NOK. */
/*  * */
/*  * XXX check for bounds */
/*  |)}># */
/* static int inc_handler(struct client *c) { */
/*  */
/*     int code = OK; */
/*     struct key_list_command *inc = c->request->command->klcommand; */
/*     bool found = false; */
/*     void *val = NULL; */
/*  */
/*     if (c->db->st_type == STORE_TRIE_TYPE) { */
/*  */
/*         for (int i = 0; i < inc->len; i++) { */
/*  */
/*             if (inc->keys[i]->is_prefix == 1) { */
/*                 trie_prefix_inc(c->db->data, (const char *) inc->keys[i]->key); */
/*             } else { */
/*  */
/*                 #<{(| */
/*                  * For each key in the keys array, check for presence and */
/*                  * increment it by one */
/*                  |)}># */
/*                 found = trie_find(c->db->data, */
/*                                   (const char *) inc->keys[i]->key, &val); */
/*  */
/*                 if (found == false || !val) { */
/*                     code = NOK; */
/*                 } else { */
/*  */
/*                     struct node_data *nd = val; */
/*  */
/*                     if (!is_integer(nd->data)) */
/*                         code = NOK; */
/*                     else */
/*                         nd->data = update_integer_string(nd->data, 1); */
/*                 } */
/*             } */
/*         } */
/*     } else { */
/*  */
/*         for (int i = 0; i < inc->len; i++) { */
/*  */
/*             void *data = hashtable_get(c->db->ht_data, */
/*                                        (const char *) inc->keys[i]->key); */
/*             if (!data) */
/*                 code = NOK; */
/*             else */
/*                 data = update_integer_string(data, 1); */
/*         } */
/*     } */
/*  */
/*     int flags = inc->header->flags & F_FROMNODEREQUEST ? */
/*         F_FROMNODERESPONSE | F_FROMNODEREPLY : F_NOFLAG; */
/*  */
/*     char *tid = flags & F_FROMNODEREQUEST ? */
/*         inc->header->transaction_id : NULL; */
/*  */
/*     set_ack_reply(c, code, (const uint8_t *) tid, flags); */
/*  */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/* #<{(| */
/*  * Decrement an integer value by 1. If the string value doesn't contain a */
/*  * proper integer return a NOK. */
/*  * */
/*  * XXX check for bounds */
/*  |)}># */
/* static int dec_handler(struct client *c) { */
/*  */
/*     int code = OK; */
/*     struct key_list_command *dec = c->request->command->klcommand; */
/*     bool found = false; */
/*     void *val = NULL; */
/*  */
/*     if (c->db->st_type == STORE_TRIE_TYPE) { */
/*         for (int i = 0; i < dec->len; i++) { */
/*  */
/*             if (dec->keys[i]->is_prefix) { */
/*                 trie_prefix_dec(c->db->data, (const char *) dec->keys[i]->key); */
/*             } else { */
/*  */
/*                 #<{(| */
/*                  * For each key in the keys array, check for presence and increment */
/*                  * it by one */
/*                  |)}># */
/*                 found = trie_find(c->db->data, */
/*                                   (const char *) dec->keys[i]->key, &val); */
/*                 if (found == false || !val) { */
/*                     code = NOK; */
/*                 } else { */
/*                     struct node_data *nd = val; */
/*                     if (!is_integer(nd->data)) { */
/*                         code = NOK; */
/*                     } else { */
/*                         nd->data = update_integer_string(nd->data, -1); */
/*                     } */
/*                 } */
/*             } */
/*         } */
/*     } else { */
/*         for (int i = 0; i < dec->len; i++) { */
/*             void *data = hashtable_get(c->db->ht_data, */
/*                                        (const char *) dec->keys[i]->key); */
/*             if (!data) */
/*                 code = NOK; */
/*             else */
/*                 data = update_integer_string(data, -1); */
/*         } */
/*     } */
/*  */
/*     int flags = dec->header->flags & F_FROMNODEREQUEST ? */
/*         F_FROMNODERESPONSE | F_FROMNODEREPLY : F_NOFLAG; */
/*  */
/*     char *tid = flags & F_FROMNODEREQUEST ? */
/*         dec->header->transaction_id : NULL; */
/*  */
/*     set_ack_reply(c, code, (const uint8_t *) tid, flags); */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/* #<{(| Get the current selected DB of the requesting client |)}># */
/* static int db_handler(struct client *c) { */
/*  */
/*     struct response *response = */
/*         make_data_response((uint8_t *) c->db->name, NULL, F_NOFLAG); */
/*  */
/*     struct buffer *buffer = buffer_new(response->dcontent->header->size); */
/*     pack_response(buffer, response); */
/*  */
/*     set_reply(c, buffer); */
/*     free_response(response); */
/*  */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/* #<{(| Set the current selected namespace for the connected client. |)}># */
/* static int use_handler(struct client *c) { */
/*  */
/*     struct key_command *cmd = c->request->command->kcommand; */
/*  */
/*     #<{(| Check for presence first |)}># */
/*     struct database *database = */
/*         hashtable_get(triedb.dbs, (const char *) cmd->key); */
/*  */
/*     #<{(| */
/*      * It doesn't exist, we create a new database with the given name, */
/*      * otherwise just assign it to the current db of the client */
/*      |)}># */
/*     if (!database) { */
/*         // TODO check for OOM */
/*         database = tmalloc(sizeof(*database)); */
/*         database->name = tstrdup((const char *) cmd->key); */
/*         database->st_type = cmd->is_prefix ? STORE_HT_TYPE : STORE_TRIE_TYPE; */
/*  */
/*         if (database->st_type == STORE_HT_TYPE) */
/*             database->ht_data = hashtable_new(NULL); */
/*         else */
/*             database->data = trie_new(); */
/*  */
/*         // Add it to the databases table */
/*         hashtable_put(triedb.dbs, tstrdup(database->name), database); */
/*         c->db = database; */
/*     } else { */
/*         c->db = database; */
/*     } */
/*  */
/*     set_ack_reply(c, OK, NULL, F_NOFLAG); */
/*  */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/*  */
/* static int count_handler(struct client *c) { */
/*  */
/*     int count = 0; */
/*     struct key_command *cnt = c->request->command->kcommand; */
/*  */
/*     #<{(| */
/*      * Get the size of each key below the requested one, glob operation or the */
/*      * entire trie size in case of NULL key */
/*      |)}># */
/*     if (c->db->st_type == STORE_HT_TYPE) */
/*         count = hashtable_size(c->db->ht_data); */
/*     else */
/*         count = !cnt->key ? c->db->data->size : */
/*             trie_prefix_count(c->db->data, (const char *) cnt->key); */
/*  */
/*     int flags = cnt->header->flags & F_FROMNODEREQUEST ? */
/*         F_FROMNODERESPONSE : F_NOFLAG; */
/*  */
/*     char *tid = flags & F_FROMNODEREQUEST ? */
/*         cnt->header->transaction_id : NULL; */
/*  */
/*     struct header hdr; */
/*     struct response resp = { */
/*         .vcontent = &(struct value_content) { */
/*             .header = &hdr, */
/*             .val = count */
/*         } */
/*     }; */
/*  */
/*     value_response_init(&resp, count, flags, tid); */
/*  */
/*     struct buffer *b = buffer_new(resp.vcontent->header->size); */
/*     pack_response(b, &resp); */
/*     set_reply(c, b); */
/*  */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/* } */
/*  */
/*  */
/* static int cluster_join_handler(struct client *c) { */
/*  */
/*     struct keyval_command *command = c->request->command->kvcommand; */
/*  */
/*     #<{(| Only other nodes are enabled to send this request |)}># */
/*     if (!(command->header->flags & F_FROMNODEREQUEST)) */
/*         goto exit; */
/*  */
/*     #<{(| UUID for the transaction, only for cluster operations |)}># */
/*     char uuid[UUID_LEN]; */
/*     generate_uuid(uuid); */
/*     // TODO add it to the global map */
/*  */
/*     if (command->header->flags & F_JOINREQUEST) { */
/*  */
/*         // Send here the list of the other cluster members */
/*         List *members = list_new(keyval_list_free); */
/*         List *cluster_nodes = triedb.cluster->nodes; */
/*  */
/*         for (struct list_node *ln = cluster_nodes->head; ln; ln = ln->next) { */
/*  */
/*             struct cluster_node *curr_node = ln->data; */
/*  */
/*             if (curr_node->self || curr_node->vnode) */
/*                 continue; */
/*  */
/*             struct keyval *kv = tmalloc(sizeof(*kv)); */
/*             kv->keysize = strlen(curr_node->host); */
/*             kv->key = (uint8_t *) tstrdup(curr_node->host); */
/*             kv->valsize = strlen(curr_node->port); */
/*             kv->val = (uint8_t *) tstrdup(curr_node->port); */
/*  */
/*             list_push(members, kv); */
/*         } */
/*  */
/*         if (list_size(members) > 0) { */
/*             struct response *response = */
/*                 make_kvlist_response(members, (const uint8_t *) uuid, */
/*                                      F_FROMNODERESPONSE | F_BULKREQUEST); */
/*  */
/*             struct buffer *buffer = */
/*                 buffer_new(response->kvlcontent->header->size); */
/*  */
/*             pack_response(buffer, response); */
/*  */
/*             set_reply(c, buffer); */
/*  */
/*             free_response(response); */
/*  */
/*         } else { */
/*             set_ack_reply(c, OK, (const uint8_t *) uuid, */
/*                           F_FROMNODERESPONSE | F_JOINREQUEST); */
/*         } */
/*  */
/*         list_destroy(members, 0); */
/*  */
/*     } else { */
/*         set_ack_reply(c, OK, (const uint8_t *) uuid, */
/*                       F_FROMNODERESPONSE | F_JOINREQUEST); */
/*     } */
/*  */
/*     #<{(| */
/*      * Add new node to the hashring of this instance, key field of the command */
/*      * structure should carry the host+port string joined together */
/*      |)}># */
/*     cluster_add_new_node(triedb.cluster, c, (const char *) command->key, */
/*                          (const char *) command->val, false); */
/*  */
/*     tdebug("New node on %s:%s UUID %s joined", */
/*            command->key, command->val, c->uuid); */
/*  */
/*     free_request(c->request); */
/*  */
/*     return OK; */
/*  */
/* exit: */
/*  */
/*     free_request(c->request); */
/*  */
/*     return -1; */
/* } */
/*  */
/*  */
/* static int cluster_members_handler(struct client *c) { */
/*  */
/*     struct kvlist_content *content = c->response->kvlcontent; */
/*  */
/*     #<{(| Only other nodes are enabled to send this response |)}># */
/*     if (!(content->header->flags & F_FROMNODERESPONSE) || content->len == 0) */
/*         return -1; */
/*  */
/*     struct keyval *pair = content->pairs[0]; */
/*  */
/*     // Connect to the first node target */
/*     int port = atoi((const char *) pair->val) + 10000; */
/*  */
/*     int fd = open_connection((const char *) pair->key, port); */
/*  */
/*     // Create a new client for it */
/*     if (set_nonblocking(fd) < 0) */
/*         perror("set_nonblocking: "); */
/*  */
/*     if (set_tcp_nodelay(fd) < 0) */
/*         perror("set_tcp_nodelay: "); */
/*  */
/*     struct client *new_node = tmalloc(sizeof(*new_node)); */
/*  */
/*     new_node->ctype = NODE; */
/*     new_node->addr = tstrdup((const char *) pair->key); */
/*     new_node->fd = fd; */
/*     new_node->last_action_time = time(NULL); */
/*     new_node->ctx_handler = read_handler; */
/*     new_node->reply = NULL; */
/*     new_node->request = NULL; */
/*     new_node->response = NULL; */
/*     new_node->db = hashtable_get(triedb.dbs, "db0"); */
/*  */
/*     generate_uuid((char *) new_node->uuid); */
/*  */
/*     if (add_epoll(triedb.epollfd, fd, EPOLLIN, new_node) < 0) */
/*         perror("epoll_add: "); */
/*  */
/*     #<{(| */
/*      * Add new node to the hashring of this instance, key field of the */
/*      * command structure should carry the host+port string joined together */
/*      |)}># */
/*     cluster_add_new_node(triedb.cluster, new_node, (const char *) pair->key, */
/*                          (const char *) pair->val, false); */
/*  */
/*     #<{(| Track the new connected node |)}># */
/*     hashtable_put(triedb.nodes, new_node->uuid, new_node); */
/*  */
/*     tdebug("New node on %s:%s UUID %s joined", */
/*            pair->key, pair->val, new_node->uuid); */
/*  */
/*     // Send CLUSTER_JOIN request */
/*     // XXX Obnoxious */
/*     struct request *request = make_join_request(conf->hostname, conf->port, */
/*                                                 F_FROMNODEREQUEST); */
/*  */
/*     ssize_t sent; */
/*     size_t rsize = request->command->kvcommand->header->size; */
/*     if ((sent = write_to_node(new_node->fd, request, */
/*                               rsize, KEY_VAL_COMMAND)) < 0) */
/*         terror("server::ack_handler: %s", strerror(errno)); */
/*  */
/*     free_request(request); */
/*  */
/*     // Update informations */
/*     info.nconnections++; */
/*     info.nnodes++; */
/*  */
/*     // XXX check */
/*     tfree(pair->key); */
/*     tfree(pair->val); */
/*     tfree(pair); */
/*  */
/*     #<{(| Push other awaiting cluster members into a connection queue |)}># */
/*     if (content->len > 1) */
/*         for (int i = 1; i < content->len; i++) */
/*             queue_push(triedb.pending_members, content->pairs[i]); */
/*  */
/*     // clean out partial structure */
/*     tfree(content->header); */
/*     tfree(content->pairs); */
/*     tfree(content); */
/*     tfree(c->response); */
/*  */
/*     return JUSTACK; */
/* } */
/*  */
/*  */
/* #<{(|************************************|)}># */
/* #<{(|          SERVER_HANDLERS           |)}># */
/* #<{(|************************************|)}># */
/*  */
/*  */
/* #<{(| */
/*  * Construct an hashtable containing all keylist request that must be sent to */
/*  * different nodes on the cluster: */
/*  * node uuid -> keylist_request */
/*  |)}># */
/* static int make_kl_reqs(struct hashtable_entry *entry, void *param) { */
/*  */
/*     if (!param || !entry || !entry->val) */
/*         return -HASHTABLE_ERR; */
/*  */
/*     #<{(| */
/*      * TODO add struct to handle: */
/*      * - a list of keys */
/*      * - a hashtable UUID -> keylists */
/*      |)}># */
/*     HashTable *kl_reqs = param; */
/*     struct multirequest *mrequest = entry->val; */
/*  */
/*     struct request *klr = hashtable_get(kl_reqs, entry->key); */
/*  */
/*     if (!klr) { */
/*         struct request *klrequest = */
/*             make_keylist_request(mrequest->keys, mrequest->opcode, */
/*                                  (const uint8_t *) mrequest->transaction_id, */
/*                                  mrequest->flags); */
/*         hashtable_put(kl_reqs, entry->key, klrequest); */
/*     } */
/*  */
/*     return HASHTABLE_OK; */
/* } */
/*  */
/*  */
/* static int route_command(struct request *request, struct client *client) { */
/*  */
/*     int ret = 0; */
/*  */
/*     if (request->reqtype == SINGLE_REQUEST) { */
/*  */
/*         #<{(| Cluster node placeholder |)}># */
/*         struct cluster_node *node = NULL; */
/*         struct command *command = request->command; */
/*         HashTable *requests; */
/*  */
/*         int16_t hashval = -1; */
/*         size_t len = 0LL; */
/*  */
/*         #<{(| */
/*          * Update cluster transactions in order to know who to answer to */
/*          * when the other node will reply back with result */
/*          |)}># */
/*         char transaction_id[UUID_LEN]; */
/*         generate_uuid(transaction_id); */
/*  */
/*         #<{(| Track the transaction |)}># */
/*         hashtable_put(triedb.transactions, tstrdup(transaction_id), client); */
/*  */
/*         switch (command->cmdtype) { */
/*             case KEY_COMMAND: */
/*  */
/*                 #<{(| */
/*                  * Compute a CRC32(key) % RING_SIZE, we get an index for a */
/*                  * position in the consistent hash ring and retrieve the node */
/*                  * in charge to handle the request */
/*                  * TODO check if the node resulted is self */
/*                  |)}># */
/*                 hashval = hash((const char *) command->kcommand->key); */
/*  */
/*                 node = cluster_get_node(triedb.cluster, hashval); */
/*  */
/*                 if (node->self) */
/*                     goto exitself; */
/*  */
/*                 #<{(| */
/*                  * Assign the generated transaction id and set the flag */
/*                  * F_FROMNODEREQUEST on, in order to make clear that we are */
/*                  * routing this request to another node. */
/*                  |)}># */
/*                 strcpy(command->kcommand->header->transaction_id, */
/*                        transaction_id); */
/*                 command->kcommand->header->flags |= F_FROMNODEREQUEST; */
/*                 command->kcommand->header->size += UUID_LEN - 1; */
/*  */
/*                 len = command->kcommand->header->size; */
/*  */
/*                 break; */
/*  */
/*             case KEY_VAL_COMMAND: */
/*  */
/*                 #<{(| */
/*                  * Compute a CRC32(key) % RING_SIZE, we get an index for a */
/*                  * position in the consistent hash ring and retrieve the node */
/*                  * in charge to handle the request */
/*                  * TODO check if the node resulted is self */
/*                  |)}># */
/*                 hashval = hash((const char *) command->kvcommand->key); */
/*  */
/*                 node = cluster_get_node(triedb.cluster, hashval); */
/*  */
/*                 if (node->self) */
/*                     goto exitself; */
/*  */
/*                 #<{(| */
/*                  * Assign the generated transaction id and set the flag */
/*                  * F_FROMNODEREQUEST on, in order to make clear that we are */
/*                  * routing this request to another node. */
/*                  |)}># */
/*                 strcpy(command->kvcommand->header->transaction_id, */
/*                        transaction_id); */
/*                 command->kvcommand->header->flags |= F_FROMNODEREQUEST; */
/*                 command->kvcommand->header->size += UUID_LEN - 1; */
/*  */
/*                 len = command->kvcommand->header->size; */
/*  */
/*                 break; */
/*  */
/*             case KEY_LIST_COMMAND: */
/*  */
/*                 // TODO add destructor function */
/*                 requests = hashtable_new(hashtable_multirequest_release); */
/*  */
/*                 for (int i = 0; i < len; i++) { */
/*  */
/*                     struct key *key = command->klcommand->keys[i]; */
/*  */
/*                     #<{(| */
/*                      * Compute a CRC32(key) % RING_SIZE, we get an index for a */
/*                      * position in the consistent hash ring and retrieve the node */
/*                      * in charge to handle the request */
/*                      * TODO check if the node resulted is self */
/*                      |)}># */
/*                     hashval = hash((const char *) key->key); */
/*  */
/*                     node = cluster_get_node(triedb.cluster, hashval); */
/*  */
/*                     #<{(| if (node->self) |)}># */
/*                     #<{(|     goto exitself; |)}># */
/*  */
/*                     #<{(| */
/*                      * Assign the generated transaction id and set the flag */
/*                      * F_FROMNODEREQUEST on, in order to make clear that we are */
/*                      * routing this request to another node. */
/*                      |)}># */
/*                     strcpy(command->klcommand->header->transaction_id, */
/*                            transaction_id); */
/*  */
/*                     command->klcommand->header->flags |= F_FROMNODEREQUEST; */
/*                     command->klcommand->header->size += UUID_LEN - 1; */
/*  */
/*                     len = command->klcommand->header->size; */
/*  */
/*                     struct multirequest *mrequest = */
/*                         hashtable_get(requests, node->link->uuid); */
/*  */
/*                     if (hashtable_size(requests) == 0 || !mrequest) { */
/*  */
/*                         #<{(| */
/*                          * Could be created on stack but on heap it's simpler */
/*                          * to destroy it after the use */
/*                          |)}># */
/*                         mrequest = tmalloc(sizeof(*mrequest)); */
/*                         mrequest->fd = node->link->fd; */
/*                         mrequest->keys = list_new(NULL);  // TODO add destructor */
/*                         mrequest->opcode = command->klcommand->header->opcode; */
/*                         mrequest->flags = command->klcommand->header->flags; */
/*                         list_push(mrequest->keys, key->key); */
/*                         strcpy(mrequest->transaction_id, transaction_id); */
/*                         hashtable_put(requests, node->link->uuid, mrequest); */
/*                     } else { */
/*                         list_push(mrequest->keys, key->key); */
/*                     } */
/*                 } */
/*  */
/*                 // Create key_list requests */
/*                 HashTable *kl_reqs = hashtable_new(NULL); */
/*  */
/*                 hashtable_map2(requests, make_kl_reqs, kl_reqs); */
/*  */
/*                 break; */
/*  */
/*             default: */
/*                 tdebug("Route command: not implemented yet"); */
/*                 break; */
/*         } */
/*  */
/*         if (!node) */
/*             goto err; */
/*  */
/*         ssize_t sent; */
/*         if ((sent = write_to_node(node->link->fd, */
/*                                   request, len, command->cmdtype)) < 0) */
/*             terror("server::ack_handler: %s", strerror(errno)); */
/*  */
/*         // Update information stats */
/*         info.noutputbytes += sent; */
/*  */
/*         tinfo("Routing to %s", node->link->uuid); */
/*     } else { */
/*         // TODO */
/*     } */
/*  */
/*     return ret; */
/*  */
/* exitself: */
/*  */
/*     return -1; */
/*  */
/* err: */
/*     return -2; */
/*  */
/* } */
/*  */
/* #<{(| Handle incoming requests, after being accepted or after a reply |)}># */
/* static int read_handler(struct client *client) { */
/*  */
/*     int clientfd = client->fd; */
/*  */
/*     #<{(| */
/*      * struct buffer to initialize the ring buffer, used to handle input from */
/*      * client */
/*      |)}># */
/*     uint8_t *buffer = tmalloc(conf->max_request_size); */
/*  */
/*     #<{(| */
/*      * Ringbuffer pointer struct, helpful to handle different and unknown */
/*      * size of chunks of data which can result in partially formed packets or */
/*      * overlapping as well */
/*      |)}># */
/*     Ringbuffer *rbuf = ringbuf_new(buffer, conf->max_request_size); */
/*  */
/*     struct packet pkt; */
/*     int rc = 0; */
/*  */
/*     #<{(| */
/*      * We must read all incoming bytes till an entire packet is received. This */
/*      * is achieved by using a custom protocol, which send the size of the */
/*      * complete packet as the first 4 bytes. By knowing it we know if the */
/*      * packet is ready to be deserialized and used. */
/*      |)}># */
/*     rc = recv_packet(clientfd, rbuf, &pkt); */
/*  */
/*     #<{(| */
/*      * Looks like we got a client disconnection. */
/*      * TODO: Set a error_handler for ERRMAXREQSIZE instead of dropping client */
/*      *       connection, explicitly returning an informative error code to the */
/*      *       client connected. */
/*      |)}># */
/*     if (rc == -ERRCLIENTDC || rc == -ERRMAXREQSIZE) { */
/*         ringbuf_destroy(rbuf); */
/*         tfree(buffer); */
/*         goto errclient; */
/*     } */
/*  */
/*     #<{(| */
/*      * If not correct packet received, we must free ringbuffer and reset the */
/*      * handler to the request again, setting EPOLL to EPOLLIN */
/*      |)}># */
/*     if (rc == -ERRPACKETERR) */
/*         goto freebuf; */
/*  */
/*     // Update information stats */
/*     info.ninputbytes += pkt.buf->size; */
/*  */
/*     #<{(| */
/*      * Currently we have a stream of bytes, we want to unpack them into a */
/*      * request structure or a response structure */
/*      |)}># */
/*     if (rc == 1) { */
/*  */
/*         struct response *response = unpack_response(pkt.buf); */
/*  */
/*         #<{(| */
/*          * If the packet couldn't be unpacked (e.g. we're OOM) we close the */
/*          * connection and release the client */
/*          |)}># */
/*         if (!response) */
/*             goto errclient; */
/*  */
/*         if ((pkt.flags & F_JOINREQUEST && pkt.opcode != ACK) */
/*             || pkt.flags & F_FROMNODEREPLY) { */
/*  */
/*             ssize_t nbytes = -1; */
/*             if ((nbytes = reply_to_client(response, pkt.buf)) > 0) */
/*                 info.noutputbytes += nbytes; */
/*  */
/*             free_response(response); */
/*  */
/*             goto reset; */
/*         } */
/*  */
/*         #<{(| Link the response to the client that sent it |)}># */
/*         client->response = response; */
/*  */
/*     } else { */
/*  */
/*         struct request *request = unpack_request(pkt.buf); */
/*  */
/*         #<{(| */
/*          * If the packet couldn't be unpacked (e.g. we're OOM) we close the */
/*          * connection and release the client */
/*          |)}># */
/*         if (!request) */
/*             goto errclient; */
/*  */
/*         #<{(| */
/*          * Link the correct structure to the client, according to the packet type */
/*          * received, this time it's a request */
/*          |)}># */
/*         client->request = request; */
/*  */
/*         #<{(| */
/*          * If the mode is cluster and the requesting client is not a node nor a */
/*          * server but another node in the cluster, we should route the command to */
/*          * the correct node before handling it. */
/*          |)}># */
/*         if (client->ctype == CLIENT && conf->mode == CLUSTER) { */
/*  */
/*             #<{(| */
/*              * The hash of the key belong to the current node, no need to */
/*              * forward the request to another node in the cluster */
/*              |)}># */
/*             if (route_command(request, client) > -1) { */
/*                 free_request(request); */
/*                 goto reset; */
/*             } */
/*         } */
/*     } */
/*  */
/*     // Update client last action time */
/*     client->last_action_time = (uint64_t) time(NULL); */
/*  */
/*     int executed = 0; */
/*     int err = 0; */
/*  */
/*     // Loop through commands_hashmap array to find the correct handler */
/*     for (int i = 0; i < COMMAND_COUNT; i++) { */
/*         if (commands_map[i].ctype == pkt.opcode) { */
/*             err = commands_map[i].handler(client); */
/*             executed = 1; */
/*         } */
/*     } */
/*  */
/*     // Record request on the counter */
/*     info.nrequests++; */
/*  */
/*     #<{(| */
/*      * If no handler is found, or the response was just a normal ACK, it must */
/*      * be an error case */
/*      |)}># */
/*     if (executed == 0 || err == JUSTACK) */
/*         goto reset; */
/*  */
/*     #<{(| */
/*      * A disconnection happened, we close the handler, the file descriptor */
/*      * have been already removed from the event loop */
/*      |)}># */
/*     if (err == -1) */
/*         goto exit; */
/*  */
/*     // Set reply handler as the current context handler */
/*     client->ctx_handler = write_handler; */
/*  */
/*     #<{(| */
/*      * Reset handler to read_handler in order to read new incoming data and */
/*      * EPOLL event for read fds */
/*      |)}># */
/*     mod_epoll(triedb.epollfd, clientfd, EPOLLOUT, client); */
/*  */
/*     #<{(| No more need of the byte buffer from now on |)}># */
/*     buffer_destroy(pkt.buf); */
/*  */
/*     #<{(| Free ring buffer as we alredy have all needed informations in memory |)}># */
/*     ringbuf_destroy(rbuf); */
/*  */
/*     tfree(buffer); */
/*  */
/* exit: */
/*  */
/*     return 0; */
/*  */
/* freebuf: */
/*  */
/*     ringbuf_destroy(rbuf); */
/*     tfree(buffer); */
/*  */
/* reset: */
/*  */
/*     #<{(| No more need of the byte buffer from now on |)}># */
/*     buffer_destroy(pkt.buf); */
/*  */
/*     #<{(| */
/*      * Free ring buffer as we alredy have all needed informations */
/*      * in memory */
/*      |)}># */
/*     ringbuf_destroy(rbuf); */
/*  */
/*     tfree(buffer); */
/*  */
/*     client->ctx_handler = read_handler; */
/*     mod_epoll(triedb.epollfd, clientfd, EPOLLIN, client); */
/*     return 0; */
/*  */
/* errclient: */
/*  */
/*     terror("Dropping client on %s", client->addr); */
/*     close(client->fd); */
/*  */
/*     if (client->ctype == NODE) */
/*         info.nnodes--; */
/*     else */
/*         info.nclients--; */
/*  */
/*     info.nconnections--; */
/*  */
/*     hashtable_del(triedb.clients, client->uuid); */
/*  */
/*     return -1; */
/* } */
/*  */
/*  */
/* #<{(| */
/*  * Handle reply state, after a request/response has been processed in */
/*  * read_handler routine. Just send out all bytes stored in the reply buffer */
/*  * to the reply file descriptor, which can be either a connected client or a */
/*  * triedb node connected to the bus port. */
/*  |)}># */
/* static int write_handler(struct client *client) { */
/*  */
/*     int rc = 0; */
/*     if (!client->reply) */
/*         return rc; */
/*  */
/*     struct reply *reply = client->reply; */
/*  */
/*     ssize_t sent; */
/*     if ((sent = send_data(reply->fd, reply->payload->data, */
/*                           reply->payload->size)) < 0) { */
/*         terror("server::write_handler %s", strerror(errno)); */
/*         rc = -1; */
/*     } */
/*  */
/*     // Update information stats */
/*     info.noutputbytes += sent; */
/*  */
/*     free_reply(client->reply); */
/*     client->reply = NULL; */
/*  */
/*     #<{(| Set up EPOLL event on EPOLLIN to read fds |)}># */
/*     client->ctx_handler = read_handler; */
/*     mod_epoll(triedb.epollfd, client->fd, EPOLLIN, client); */
/*  */
/*     return rc; */
/* } */
/*  */
/* #<{(| */
/*  * Accept a new incoming connection assigning ip address and socket descriptor */
/*  * to the connection structure pointer passed as argument */
/*  |)}># */
/* static int accept_new_client(int fd, struct connection *conn) { */
/*  */
/*     if (!conn) */
/*         return -1; */
/*  */
/*     #<{(| Accept the connection |)}># */
/*     int clientsock = accept_connection(fd); */
/*  */
/*     #<{(| Abort if not accepted |)}># */
/*     if (clientsock == -1) */
/*         return -1; */
/*  */
/*     #<{(| Just some informations retrieval of the new accepted client connection |)}># */
/*     struct sockaddr_in addr; */
/*     socklen_t addrlen = sizeof(addr); */
/*  */
/*     if (getpeername(clientsock, (struct sockaddr *) &addr, &addrlen) < 0) */
/*         return -1; */
/*  */
/*     char ip_buff[INET_ADDRSTRLEN + 1]; */
/*     if (inet_ntop(AF_INET, &addr.sin_addr, ip_buff, sizeof(ip_buff)) == NULL) */
/*         return -1; */
/*  */
/*     struct sockaddr_in sin; */
/*     socklen_t sinlen = sizeof(sin); */
/*  */
/*     if (getsockname(fd, (struct sockaddr *) &sin, &sinlen) < 0) */
/*         return -1; */
/*  */
/*     conn->fd = clientsock; */
/*     strcpy(conn->ip, ip_buff); */
/*  */
/*     return 0; */
/* } */
/*  */
/* #<{(| */
/*  * Handle new connection, create a a fresh new struct client structure and link */
/*  * it to the fd, ready to be set in EPOLLIN event */
/*  |)}># */
/* static int accept_handler(struct client *server) { */
/*  */
/*     struct connection conn; */
/*  */
/*     accept_new_client(server->fd, &conn); */
/*  */
/*     #<{(| Create a client structure to handle his context connection |)}># */
/*     struct client *client = tmalloc(sizeof(struct client)); */
/*     if (!client) */
/*         oom("creating client during accept"); */
/*  */
/*     #<{(| Generate random uuid |)}># */
/*     uuid_t binuuid; */
/*     uuid_generate_random(binuuid); */
/*     uuid_unparse(binuuid, (char *) client->uuid); */
/*  */
/*     #<{(| Populate client structure |)}># */
/*     client->ctype = CLIENT; */
/*     client->addr = tstrdup(conn.ip); */
/*     client->fd = conn.fd; */
/*     client->ctx_handler = read_handler; */
/*  */
/*     #<{(| Record last action as of now |)}># */
/*     client->last_action_time = (uint64_t) time(NULL); */
/*  */
/*     client->reply = NULL; */
/*  */
/*     #<{(| Set the default db for the current user |)}># */
/*     client->db = hashtable_get(triedb.dbs, "db0"); */
/*  */
/*     #<{(| Add it to the db instance |)}># */
/*     hashtable_put(triedb.clients, client->uuid, client); */
/*  */
/*     #<{(| Add it to the epoll loop |)}># */
/*     add_epoll(triedb.epollfd, conn.fd, EPOLLIN, client); */
/*  */
/*     #<{(| Rearm server fd to accept new connections |)}># */
/*     mod_epoll(triedb.epollfd, server->fd, EPOLLIN, server); */
/*  */
/*     #<{(| Record the new client connected |)}># */
/*     info.nclients++; */
/*     info.nconnections++; */
/*  */
/*     return 0; */
/* } */
/*  */
/* #<{(| */
/*  * Accept a triedb instance connecting from a (at least logical) separate node */
/*  * by setting the client connected as type NODE */
/*  |)}># */
/* static int accept_node_handler(struct client *bus_server) { */
/*  */
/*     struct connection conn; */
/*  */
/*     accept_new_client(bus_server->fd, &conn); */
/*  */
/*     #<{(| Create a client structure to handle his context connection |)}># */
/*     struct client *new_node = tmalloc(sizeof(struct client)); */
/*     if (!new_node) */
/*         oom("creating new_node during accept"); */
/*  */
/*     #<{(| Generate random uuid |)}># */
/*     uuid_t binuuid; */
/*     uuid_generate_random(binuuid); */
/*     uuid_unparse(binuuid, (char *) new_node->uuid); */
/*  */
/*     #<{(| Populate new_node structure |)}># */
/*     new_node->ctype = NODE; */
/*     new_node->addr = tstrdup(conn.ip); */
/*     new_node->fd = conn.fd; */
/*     new_node->ctx_handler = read_handler; */
/*  */
/*     #<{(| Record last action as of now |)}># */
/*     new_node->last_action_time = (uint64_t) time(NULL); */
/*  */
/*     new_node->reply = NULL; */
/*  */
/*     #<{(| Set the default db for the current user |)}># */
/*     new_node->db = hashtable_get(triedb.dbs, "db0"); */
/*  */
/*     #<{(| Add it to the db instance |)}># */
/*     hashtable_put(triedb.nodes, new_node->uuid, new_node); */
/*  */
/*     #<{(| Add it to the epoll loop |)}># */
/*     add_epoll(triedb.epollfd, conn.fd, EPOLLIN, new_node); */
/*  */
/*     #<{(| Rearm server fd to accept new connections |)}># */
/*     mod_epoll(triedb.epollfd, bus_server->fd, EPOLLIN, bus_server); */
/*  */
/*     #<{(| Record the new node connected |)}># */
/*     info.nnodes++; */
/*     info.nconnections++; */
/*  */
/*     return 0; */
/*  */
/* } */
/*  */
/*  */
/* static void free_expiring_keys(Vector *ekeys) { */
/*  */
/*     if (!ekeys) */
/*         return; */
/*  */
/*     struct expiring_key *ek = NULL; */
/*  */
/*     for (int i = 0; i < ekeys->size; i++) { */
/*  */
/*         ek = vector_get(ekeys, i); */
/*  */
/*         if (!ek) */
/*             continue; */
/*  */
/*         if (ek->key) */
/*             tfree((char *) ek->key); */
/*  */
/*         tfree(ek); */
/*     } */
/*  */
/*     // free vector structure pointer */
/*     tfree(ekeys->items); */
/*     tfree(ekeys); */
/* } */
/*  */
/* #<{(| */
/*  * Cycle through sorted list of expiring keys and remove those which are */
/*  * elegible */
/*  |)}># */
/* static void expire_keys(void) { */
/*  */
/*     if (vector_size(triedb.expiring_keys) == 0) */
/*         return; */
/*  */
/*     int64_t now = (int64_t) time(NULL); */
/*     int64_t delta = 0LL; */
/*     struct expiring_key *ek = NULL; */
/*  */
/*     for (int i = 0; i < vector_size(triedb.expiring_keys); i++) { */
/*  */
/*         ek = vector_get(triedb.expiring_keys, i); */
/*         delta = (ek->nd->ctime + ek->nd->ttl) - now; */
/*  */
/*         if (delta > 0) */
/*             break; */
/*  */
/*         #<{(| */
/*          * ek->data_ptr points to the trie of the client which stores the given */
/*          * key */
/*          |)}># */
/*         trie_delete(ek->data_ptr, ek->key); */
/*  */
/*         vector_delete(triedb.expiring_keys, i); */
/*  */
/*         // Update total keyspace counter */
/*         triedb.keyspace_size--; */
/*  */
/*         tdebug("%s expired", ek->key); */
/*  */
/*         tfree((char *) ek->key); */
/*         tfree(ek); */
/*         ek = NULL; */
/*     } */
/* } */
/*  */
/* #<{(| Print and log some basic stats |)}># */
/* static inline void log_stats(void) { */
/*     info.uptime = time(NULL) - info.start_time; */
/*     const char *uptime = time_to_string(info.uptime); */
/*     const char *memory = memory_to_string(memory_used()); */
/*     char cnodes[17 + number_len(info.nnodes) + 1]; */
/*     sprintf(cnodes, "connected nodes: %d", info.nnodes); */
/*     tdebug("Connected clients: %d %s total connections: %d " */
/*            "requests: %d dbs: %ld keys: %ld memory usage: %s  uptime: %s", */
/*            info.nclients, conf->mode == CLUSTER ? cnodes : "", */
/*            info.nconnections, info.nrequests, triedb.dbs->size, */
/*            triedb.keyspace_size, memory, uptime); */
/*     tfree((char *) uptime); */
/*     tfree((char *) memory); */
/* } */
/*  */
/* #<{(| */
/*  * Temporary auxiliary function till the network::epoll_loop is ready, add a */
/*  * periodic task to the epoll loop */
/*  |)}># */
/* static int add_cron_task(int epollfd, struct itimerspec timervalue) { */
/*  */
/*     int timerfd = timerfd_new(CLOCK_MONOTONIC, 0); */
/*  */
/*     if (timerfd_settime(timerfd, 0, &timervalue, NULL) < 0) */
/*         perror("timerfd_settime"); */
/*  */
/*     // Add the timer to the event loop */
/*     struct epoll_event ev; */
/*     ev.data.fd = timerfd; */
/*     ev.events = EPOLLIN; */
/*  */
/*     if (epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &ev) < 0) { */
/*         perror("epoll_ctl(2): EPOLLIN"); */
/*         return -1; */
/*     } */
/*  */
/*     return timerfd; */
/* } */
/*  */
/* #<{(| */
/*  * Main worker function, his responsibility is to wait on events on a shared */
/*  * EPOLL fd, use the same way for clients or peer to distribute messages */
/*  |)}># */
/* static void run_server(void) { */
/*  */
/*     struct epoll_event *evs = tmalloc(sizeof(*evs) * MAX_EVENTS); */
/*  */
/*     if (!evs) */
/*         oom("allocating events"); */
/*  */
/*     int timeout = conf->epoll_timeout; */
/*     int events = 0; */
/*  */
/*     struct itimerspec timervalue; */
/*  */
/*     memset(&timervalue, 0x00, sizeof(timervalue)); */
/*  */
/*     timervalue.it_value.tv_sec = 0; */
/*     timervalue.it_value.tv_nsec = TTL_CHECK_INTERVAL; */
/*     timervalue.it_interval.tv_sec = 0; */
/*     timervalue.it_interval.tv_nsec = TTL_CHECK_INTERVAL; */
/*  */
/*     // add expiration keys cron task */
/*     int exptimerfd = add_cron_task(triedb.epollfd, timervalue); */
/*  */
/*     int statstimerfd = -1; */
/*     if (conf->loglevel == DEBUG) { */
/*         struct itimerspec st_timervalue; */
/*  */
/*         memset(&timervalue, 0x00, sizeof(st_timervalue)); */
/*  */
/*         st_timervalue.it_value.tv_sec = STATS_PRINT_INTERVAL; */
/*         st_timervalue.it_value.tv_nsec = 0; */
/*         st_timervalue.it_interval.tv_sec = STATS_PRINT_INTERVAL; */
/*         st_timervalue.it_interval.tv_nsec = 0; */
/*  */
/*         statstimerfd = add_cron_task(triedb.epollfd, st_timervalue); */
/*     } */
/*  */
/*     long int timers = 0; */
/*  */
/*     while (1) { */
/*  */
/*         events = epoll_wait(triedb.epollfd, evs, MAX_EVENTS, timeout); */
/*  */
/*         if (events < 0) { */
/*             if (errno == EINTR) { */
/*                 continue; */
/*             } */
/*             break; */
/*         } */
/*  */
/*         for (int i = 0; i < events; i++) { */
/*  */
/*             #<{(| Check for errors first |)}># */
/*             if ((evs[i].events & EPOLLERR) || */
/*                 (evs[i].events & EPOLLHUP) || */
/*                 (!(evs[i].events & EPOLLIN) && !(evs[i].events & EPOLLOUT))) { */
/*  */
/*                 #<{(| */
/*                  * An error has occured on this fd, or the socket is not ready */
/*                  * for reading */
/*                  |)}># */
/*                 struct client *client = evs[i].data.ptr; */
/*  */
/*                 terror("Dropping client on %s: event polling error %s", */
/*                        client->addr, strerror(errno)); */
/*  */
/*                 #<{(| */
/*                  * Clean out from global tables, from clients or from nodes */
/*                  * based on the client type */
/*                  * TODO: unify with if below */
/*                  |)}># */
/*                 if (client->ctype == NODE) */
/*                     info.nnodes--; */
/*                 else */
/*                     info.nclients--; */
/*  */
/*                 info.nconnections--; */
/*  */
/*                 hashtable_del(client->ctype == NODE ? */
/*                               triedb.nodes : triedb.clients, client->uuid); */
/*  */
/*                 close(evs[i].data.fd); */
/*  */
/*                 continue; */
/*  */
/*             } else if (evs[i].data.fd == conf->run) { */
/*  */
/*                 #<{(| And quit event after that |)}># */
/*                 eventfd_t val; */
/*                 eventfd_read(conf->run, &val); */
/*  */
/*                 tdebug("Stopping epoll loop."); */
/*  */
/*                 goto exit; */
/*  */
/*             } else if (exptimerfd != -1 && evs[i].data.fd == exptimerfd) { */
/*                 (void) read(evs[i].data.fd, &timers, 8); */
/*                 // Check for keys about to expire out */
/*                 expire_keys(); */
/*             } else if (statstimerfd != -1 && evs[i].data.fd == statstimerfd) { */
/*                 (void) read(evs[i].data.fd, &timers, 8); */
/*                 // Print stats about the server */
/*                 log_stats(); */
/*             } else { */
/*                 #<{(| Finally handle the request according to its type |)}># */
/*                 ((struct client *) evs[i].data.ptr)->ctx_handler(evs[i].data.ptr); */
/*             } */
/*         } */
/*     } */
/*  */
/* exit: */
/*  */
/*     if (events <= 0 && conf->run != 1) */
/*         perror("epoll_wait(2) error"); */
/*  */
/*     tfree(evs); */
/* } */
/*  */
/* #<{(| */
/*  * Main entry point for start listening on a socket and running an epoll event */
/*  * loop his main responsibility is to pass incoming client connections */
/*  * descriptor to workers thread. */
/*  * In this case there's no threads and uses just a single thread with */
/*  * multiplexing I/O, but it's trivial to transform the main run_server routine */
/*  * into a thread worker and launch some more (e.g. one per CPU core). */
/*  * */
/*  * Accepts two mandatory string arguments, addr and port, in case of UNIX */
/*  * domain socket, addr represents the path on the FS where the socket fd is */
/*  * located, port will be ignored. */
/*  |)}># */
/* int start_server(const char *addr, const char *port, */
/*                  struct seed_node *seednode) { */
/*  */
/*     #<{(| Initialize SizigyDB server object |)}># */
/*     triedb.clients = hashtable_new(hashtable_client_free); */
/*     triedb.nodes = hashtable_new(hashtable_client_free); */
/*     triedb.expiring_keys = vector_new(); */
/*     triedb.dbs = hashtable_new(database_free); */
/*     triedb.keyspace_size = 0LL; */
/*     // TODO add free cluster */
/*     triedb.cluster = &(struct cluster) { 0, 4, list_new(NULL) }; */
/*     triedb.transactions = hashtable_new(hashtable_transaction_free); */
/*     triedb.pending_members = queue_new(keyval_queue_free); */
/*  */
/*     #<{(| Create default database |)}># */
/*     struct database *default_db = tmalloc(sizeof(struct database)); */
/*     default_db->st_type = STORE_TRIE_TYPE; */
/*     default_db->name = tstrdup("db0"); */
/*     default_db->data = trie_new(); */
/*  */
/*     #<{(| Add it to the global map |)}># */
/*     hashtable_put(triedb.dbs, tstrdup(default_db->name), default_db); */
/*  */
/*     #<{(| Initialize epollfd for server component |)}># */
/*     int epollfd = epoll_create1(0); */
/*  */
/*     if (epollfd == -1) { */
/*         perror("epoll_create1"); */
/*         goto cleanup; */
/*     } */
/*  */
/*     triedb.epollfd = epollfd; */
/*  */
/*     #<{(| Initialize the sockets, first the server one |)}># */
/*     int fd = make_listen(addr, port, conf->socket_family); */
/*  */
/*     #<{(| */
/*      * Add eventfd to the loop, this time only in LT in order to wake up all */
/*      * threads */
/*      |)}># */
/*     struct epoll_event ev; */
/*     ev.data.fd = conf->run; */
/*     ev.events = EPOLLIN; */
/*  */
/*     if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conf->run, &ev) < 0) */
/*         perror("epoll_ctl(2): add epollin"); */
/*  */
/*     #<{(| */
/*      * Client structure for the server component, start in the ACCEPT state, */
/*      * ready to accept new connections from client and handle commands. */
/*      |)}># */
/*     struct client server = { */
/*         .ctype = SERVER, */
/*         .addr = addr, */
/*         .fd = fd, */
/*         .last_action_time = time(NULL), */
/*         .ctx_handler = accept_handler, */
/*         .reply = NULL, */
/*         .request = NULL, */
/*         .response = NULL, */
/*         .db = NULL */
/*     }; */
/*  */
/*     generate_uuid((char *) server.uuid); */
/*  */
/*     #<{(| Set socket in EPOLLIN flag mode, ready to read data |)}># */
/*     add_epoll(epollfd, fd, EPOLLIN, &server); */
/*  */
/*     #<{(| */
/*      * Add socket for bus communication if accepted by a seed node */
/*      * TODO make it in another thread or better, crate a usable client */
/*      * structure like if it was accepted as a new connection, cause actually */
/*      * it crashes the server by having NULL ptr */
/*      |)}># */
/*     if (seednode->fd > 0) { */
/*  */
/*         struct client *node = tmalloc(sizeof(*node)); */
/*  */
/*         if (set_nonblocking(seednode->fd) < 0) */
/*             perror("set_nonblocking: "); */
/*  */
/*         if (set_tcp_nodelay(seednode->fd) < 0) */
/*             perror("set_tcp_nodelay: "); */
/*  */
/*         node->ctype = NODE; */
/*         node->addr = tstrdup(seednode->addr); */
/*         node->fd = seednode->fd; */
/*         node->last_action_time = time(NULL); */
/*         node->ctx_handler = write_handler; */
/*         node->reply = NULL; */
/*         node->request = NULL; */
/*         node->response = NULL; */
/*         node->db = hashtable_get(triedb.dbs, "db0"); */
/*  */
/*         generate_uuid((char *) node->uuid); */
/*  */
/*         if (add_epoll(epollfd, seednode->fd, EPOLLOUT, node) < 0) */
/*             perror("epoll_add: "); */
/*  */
/*         // Send CLUSTER_JOIN request */
/*         // XXX Obnoxious */
/*         struct request *request = */
/*             make_join_request(addr, port, */
/*                               F_FROMNODEREQUEST | F_JOINREQUEST); */
/*  */
/*         struct buffer *buffer = */
/*             buffer_new(request->command->kvcommand->header->size); */
/*  */
/*         pack_request(buffer, request, KEY_VAL_COMMAND); */
/*  */
/*         set_reply(node, buffer); */
/*  */
/*         free_request(request); */
/*  */
/*         // Update informations */
/*         info.nconnections++; */
/*         info.nnodes++; */
/*  */
/*         // Add target node as cluster node */
/*         cluster_add_new_node(triedb.cluster, node, */
/*                              seednode->addr, seednode->port, false); */
/*  */
/*         #<{(| Track the new connected node on the cluster |)}># */
/*         hashtable_put(triedb.nodes, node->uuid, node); */
/*  */
/*         tdebug("New node on %s:%s UUID %s joined", */
/*                seednode->addr, seednode->port, node->uuid); */
/*     } */
/*  */
/*     #<{(| */
/*      * If it is run in CLUSTER mode add an additional descriptor and register */
/*      * it to the event loop, ready to accept incoming connections from other */
/*      * triedb nodes and handle cluster commands. */
/*      |)}># */
/*     if (conf->mode == CLUSTER) { */
/*  */
/*         struct client *bus_server = tmalloc(sizeof(*bus_server)); */
/*  */
/*         #<{(| Add 10k to the listening server port |)}># */
/*         int bport = atoi(port) + 10000; */
/*         snprintf(triedb.busport, number_len(bport), "%d", bport); */
/*  */
/*         #<{(| The bus one for distribution |)}># */
/*         int bfd = make_listen(addr, triedb.busport, INET); */
/*  */
/*         #<{(| struct client structure for the bus server component |)}># */
/*         bus_server->ctype = SERVER; */
/*         bus_server->addr = tstrdup(addr); */
/*         bus_server->fd = bfd; */
/*         bus_server->last_action_time = time(NULL); */
/*         bus_server->ctx_handler = accept_node_handler; */
/*         bus_server->reply = NULL; */
/*         bus_server->request = NULL; */
/*         bus_server->response = NULL; */
/*         bus_server->db = NULL; */
/*  */
/*         generate_uuid((char *) bus_server->uuid); */
/*  */
/*         #<{(| Set bus socket in EPOLLIN too |)}># */
/*         add_epoll(triedb.epollfd, bfd, EPOLLIN, bus_server); */
/*  */
/*         cluster_add_new_node(triedb.cluster, bus_server, addr, port, true); */
/*  */
/*         #<{(| Track the new connected node on the cluster |)}># */
/*         hashtable_put(triedb.nodes, bus_server->uuid, bus_server); */
/*  */
/*         tdebug("Joined a cluster"); */
/*     } */
/*  */
/*     tinfo("triedb v%s", conf->version); */
/*  */
/*     if (conf->socket_family == UNIX) */
/*         tinfo("Starting server on %s", addr); */
/*     else */
/*         tinfo("Starting server on %s:%s", addr, port); */
/*  */
/*     if (conf->mode == CLUSTER) */
/*         tinfo("Opened bus port on %s:%s", addr, triedb.busport); */
/*  */
/*     // Record start time */
/*     info.start_time = time(NULL); */
/*  */
/*     // Start spinning the ferry-wheel! */
/*     run_server(); */
/*  */
/* cleanup: */
/*  */
/*     #<{(| Free all resources allocated |)}># */
/*     hashtable_destroy(triedb.nodes); */
/*     hashtable_destroy(triedb.clients); */
/*     hashtable_destroy(triedb.transactions); */
/*     hashtable_destroy(triedb.dbs); */
/*     queue_destroy(triedb.pending_members); */
/*     list_destroy(triedb.cluster->nodes, 1); */
/*     free_expiring_keys(triedb.expiring_keys); */
/*  */
/*     tdebug("Bye\n"); */
/*     return 0; */
/* } */
