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

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include "list.h"
#include "util.h"
#include "server.h"
#include "ringbuf.h"
#include "network.h"
#include "protocol.h"


// Reference to the config structure, could be refactored lately to a more
// structured configuration
struct config config;


static void free_reply(Reply **);
static void free_client(Client **);
static int reply_handler(TriteDB *, Client *);
static int accept_handler(TriteDB *, Client *);
static int request_handler(TriteDB *, Client *);

// Commands
static int put_handler(TriteDB *, Client *);
static int get_handler(TriteDB *, Client *);
static int del_handler(TriteDB *, Client *);

// Fixed size of the header of each packet, consists of essentially the first
// 5 bytes containing respectively the type of packet (PUT, GET, DEL etc ...)
// and the total length in bytes of the packet
static const int HEADLEN = sizeof(uint8_t) + sizeof(uint32_t);

/* Parse header, require at least the first 5 bytes in order to read packet
   type and total length that we need to recv to complete the packet */
Buffer *recv_packet(const int clientfd, Ringbuffer *rbuf, uint8_t *opcode) {

    size_t n = 0;
    uint8_t read_all = 0;

    while (n < HEADLEN) {
        /* Read first 5 bytes to get the total len of the packet */
        n += recvbytes(clientfd, rbuf, read_all, HEADLEN);
        if (n < 0) {
            shutdown(clientfd, 0);
            close(clientfd);
            // TODO: remove client from config
            return NULL;
        } else if (n == 0) {
            return NULL;
        }
    }

    uint8_t tmp[ringbuf_size(rbuf)];
    uint8_t *bytearray = tmp;

    /* Try to read at least length of the packet */
    for (uint8_t i = 0; i < HEADLEN; i++)
        ringbuf_pop(rbuf, bytearray++);

    uint8_t *opc = (uint8_t *) tmp;
    uint32_t tlen = ntohl(*((uint32_t *) (tmp + sizeof(uint8_t))));

    /* Read remaining bytes to complete the packet */
    while (ringbuf_size(rbuf) < tlen - HEADLEN) {
        if ((n = recvbytes(clientfd, rbuf, read_all, tlen - HEADLEN)) < 0) {
            shutdown(clientfd, 0);
            close(clientfd);
            // TODO: remove client from config
            return NULL;
        }
    }

    /* Allocate a buffer to fit the entire packet */
    Buffer *b = buffer_init(tlen);

    /* Copy previous read part of the header (first 5 bytes) */
    memcpy(b->data, tmp, HEADLEN);

    /* Move forward pointer after HEADLEN bytes */
    bytearray = b->data + HEADLEN;

    /* Empty the rest of the ring buffer */
    while ((tlen - HEADLEN) > 0) {
        ringbuf_pop(rbuf, bytearray++);
        --tlen;
    }

    *opcode = *opc;

    return b;
}

/* Build a reply object and link it to the Client pointer */
static void set_reply(Client *c, Buffer *payload) {
    Reply *r = malloc(sizeof(*r));
    if (!r) oom("setting reply");

    r->fd = c->fd;
    r->payload = payload;

    c->reply = r;
}


static void free_reply(Reply **r) {
    if (!*r)
        return;
    if ((*r)->payload)
        buffer_destroy((*r)->payload);
    free(*r);
    *r = NULL;
}


static void free_client(Client **c) {
    if (!*c)
        return;
    if ((*c)->addr) {
        free((char *) (*c)->addr);
        (*c)->addr = NULL;
    }
    if ((*c)->reply) {
        free_reply(&(*c)->reply);
        (*c)->reply = NULL;
    }
    free(*c);
    *c = NULL;
}


static int put_handler(TriteDB *db, Client *c) {
    Put *p = (Put *) c->ptr;
    trie_insert(db->data, (const char *) p->key, p->value);
    Ack *ack = ack_packet(OK);
    Buffer *b = buffer_init(ack->header->size);
    pack_ack(b, ack);
    DEBUG("PUT %s -> %s Trie size %d", p->key, p->value, db->data->size);
    set_reply(c, b);
    free(p->header);
    free(p->key);
    free(p);
    free_ack(&ack);
    return OK;
}


static int get_handler(TriteDB *db, Client *c) {
    Get *g = (Get *) c->ptr;
    void *val = NULL;
    bool found = trie_search(db->data, (const char *) g->key, &val);
    if (found == false || val == NULL) {
        Nack *nack = ack_packet(NOK);
        Buffer *b = buffer_init(nack->header->size);
        pack_ack(b, nack);
        set_reply(c, b);
        DEBUG("GET %s -> not found Trie size %d", g->key, db->data->size);
        free_ack(&nack);
    } else {
        struct NodeData *nd = (struct NodeData *) val;
        Put *put = put_packet(g->key, nd->data);
        Buffer *b = buffer_init(put->header->size);
        pack_put(b, put);
        DEBUG("GET %s -> %s Trie size %d", put->key, nd->data, db->data->size);
        set_reply(c, b);
        free_put(&put);
    }
    free_get(&g);
    return OK;
}


static int exp_handler(TriteDB *db, Client *c) {
    Exp *e = (Exp *) c->ptr;
    void *val = NULL;
    bool found = trie_search(db->data, (const char *) e->key, &val);
    if (found == false || val == NULL) {
        Nack *nack = ack_packet(NOK);
        Buffer *b = buffer_init(nack->header->size);
        pack_ack(b, nack);
        set_reply(c, b);
        DEBUG("EXP %s -> not found Trie size %d", e->key, db->data->size);
        free_ack(&nack);
    } else {
        struct NodeData *nd = (struct NodeData *) val;
        nd->ttl = e->ttl;
        nd->ctime = (uint64_t) time(NULL);
        struct ExpiringKey *ek = malloc(sizeof(*ek));
        ek->nd = nd;
        ek->key = strdup((const char *) e->key);
        db->expiring_keys = list_push(db->expiring_keys, ek);
        if (db->expiring_keys->len > 1)
            db->expiring_keys->head = merge_sort(db->expiring_keys->head);
        Ack *ack = ack_packet(OK);
        Buffer *b = buffer_init(ack->header->size);
        pack_ack(b, ack);
        DEBUG("EXPIRE %s -> %s in %d Trie size %d", e->key, nd->data, e->ttl, db->data->size);
        set_reply(c, b);
        free_ack(&ack);
    }
    free_exp(&e);
    return OK;
}


static int del_handler(TriteDB *db, Client *c) {
    int code = OK;
    Del *d = c->ptr;
    bool found = false;
    for (int i = 0; i < d->len; i++) {
        found = trie_delete(db->data, (const char *) d->keys[i]->key);
        if (found == false) {
            code = NOK;
            DEBUG("DEL %s failed Trie size %d", d->keys[i]->key, db->data->size);
        } else {
            DEBUG("DEL %s Trie size %d", d->keys[i]->key, db->data->size);
        }
    }
    Ack *ack = ack_packet(code);
    Buffer *b = buffer_init(ack->header->size);
    pack_ack(b, ack);
    set_reply(c, b);
    free_ack(&ack);
    free_del(&d);
    return OK;
}


/* Static command map */
static struct command commands_map[] = {
    {PUT, put_handler},
    {GET, get_handler},
    {DEL, del_handler},
    {EXP, exp_handler}
};


static int commands_map_len(void) {
    return sizeof(commands_map) / sizeof(struct command);
}

/* Handle incoming requests, after being accepted or after a reply */
static int request_handler(TriteDB *db, Client *client) {

    const int clientfd = client->fd;

    /* Buffer to initialize the ring buffer, used to handle input from client */
    uint8_t buffer[ONEMB * 2];

    /* Ringbuffer pointer struct, helpful to handle different and unknown
       size of chunks of data which can result in partially formed packets or
       overlapping as well */
    Ringbuffer *rbuf = ringbuf_init(buffer, ONEMB * 2);

    /* Read all data to form a packet flag */
    int read_all = -1;

    /* Placeholders structures, at this point we still don't know if we got a
       request or a response */
    uint8_t opcode = 0;

    /* We must read all incoming bytes till an entire packet is received. This
       is achieved by using a standardized protocol, which send the size of the
       complete packet as the first 4 bytes. By knowing it we know if the packet is
       ready to be deserialized and used.*/
    Buffer *b = recv_packet(clientfd, rbuf, &opcode);

    if (!b) {
        client->ctx_handler = request_handler;
        mod_epoll(db->epollfd, clientfd, EPOLLIN, client);
        ringbuf_free(rbuf);
        return 0;
    }

    void *pkt = unpack(opcode, b);

    if (!pkt) read_all = 1;

    buffer_destroy(b);

    /* Free ring buffer as we alredy have all needed informations in memory */
    ringbuf_free(rbuf);

    if (read_all == 1)
        return -1;

    client->last_action_time = (uint64_t) time(NULL);

    /* Link the correct structure to the client, according to the packet type
       received */
    client->ptr = pkt;

    int executed = 0;

    // Loop through commands_hashmap array to find the correct handler
    for (int i = 0; i < commands_map_len(); i++) {
        if (commands_map[i].ctype == opcode) {
            commands_map[i].handler(db, client);
            executed = 1;
        }
    }

    // If no handler is found, it must be an error case
    if (executed == 0)
        ERROR("Unknown command");

    // Set reply handler as the current context handler
    client->ctx_handler = reply_handler;

    // Set up epoll events
    mod_epoll(db->epollfd, clientfd, EPOLLOUT, client);

    return 0;
}


/* Handle reply state, after a request/response has been processed in
   request_handler routine */
static int reply_handler(TriteDB *db, Client *client) {

    int ret = 0;
    if (!client->reply)
        return ret;

    Reply *reply = client->reply;
    ssize_t sent;

    if ((sendall(reply->fd, reply->payload->data,
                    reply->payload->size, &sent)) < 0) {
        perror("send(2): can't write on socket descriptor");
        ret = -1;
    }

    free_reply(&client->reply);

    /* Set up EPOLL event for read fds */
    client->ctx_handler = request_handler;
    mod_epoll(db->epollfd, client->fd, EPOLLIN, client);
    return ret;
}

/* Handle new connection, create a a fresh new Client structure and link it
   to the fd, ready to be set in EPOLLIN event */
static int accept_handler(TriteDB *db, Client *server) {
    const int fd = server->fd;

    /* Accept the connection */
    int clientsock = accept_connection(fd);

    /* Abort if not accepted */
    if (clientsock == -1)
        return -1;

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    if (getpeername(clientsock, (struct sockaddr *) &addr, &addrlen) < 0)
        return -1;

    char ip_buff[INET_ADDRSTRLEN + 1];
    if (inet_ntop(AF_INET, &addr.sin_addr, ip_buff, sizeof(ip_buff)) == NULL)
        return -1;

    struct sockaddr_in sin;
    socklen_t sinlen = sizeof(sin);

    if (getsockname(fd, (struct sockaddr *) &sin, &sinlen) < 0)
        return -1;

    /* Create a server structure to handle his context connection */
    Client *client = malloc(sizeof(Client));
    if (!client) oom("creating client during accept");

    client->addr = strdup(ip_buff);
    client->fd = clientsock;
    client->ctx_handler = request_handler;

    client->last_action_time = (uint64_t) time(NULL);

    client->reply = NULL;

    /* Add it to the db instance */
    db->clients = list_push(db->clients, client);

    /* Add it to the epoll loop */
    add_epoll(db->epollfd, clientsock, client);

    /* Rearm server fd to accept new connections */
    mod_epoll(db->epollfd, fd, EPOLLIN, server);

    return 0;
}


static int compare_node(void *arg1, void *arg2) {
    ListNode *n1 = arg1;
    ListNode *n2 = arg2;
    struct ExpiringKey *ek1 = (struct ExpiringKey *) n1->data;
    struct ExpiringKey *ek2 = (struct ExpiringKey *) n2->data;
    if (strcmp(ek1->key, ek2->key) == 0)
        return 0;
    return -1;
}


static void free_expiring_keys(List *ekeys) {

    if (!ekeys)
        return;
    struct ExpiringKey *ek = NULL;

    ListNode *h = ekeys->head;
    ListNode *tmp;

    // free all nodes
    while (ekeys->len--) {

        tmp = h->next;

        if (h) {
            if (h->data) {
                ek = h->data;
                free((char *) ek->key);
                free(ek);
            }
            free(h);
        }

        h = tmp;
    }

    // free List structure pointer
    free(ekeys);
}


static void expire_keys(TriteDB *db) {
    uint64_t now = (uint64_t) time(NULL);
    uint64_t delta = 0LL;
    struct ExpiringKey *ek = NULL;
    if (db->expiring_keys->len > 0) {
        for (ListNode *n = db->expiring_keys->head; n != NULL
                && db->expiring_keys->len > 0; n = n->next) {
            ek = n->data;
            // Skip case of no ttl set (e.g. TTL=0)
            if (ek->nd->ttl == NOTTL)
                continue;
            delta = (ek->nd->ctime + ek->nd->ttl) - now;
            if (delta <= 0) {
                trie_delete(db->data, ek->key);
                ListNode delnode = { ek, NULL };
                if (n == db->expiring_keys->head)
                    db->expiring_keys->head = n =
                        list_remove(db->expiring_keys->head, &delnode, compare_node);
                else
                    db->expiring_keys->head =
                        list_remove(db->expiring_keys->head, &delnode, compare_node);
                DEBUG("%s expired", ek->key);
                free((char *) ek->key);
                free(ek);
                ek = NULL;
                if (!db->expiring_keys->head || !db->expiring_keys->head->next)
                    break;
            } else {
                break;
            }
        }
    }
}

/* Main worker function, his responsibility is to wait on events on a shared
   EPOLL fd, use the same way for clients or peer to distribute messages */
static void *run_server(TriteDB *db) {

    struct epoll_event *evs = malloc(sizeof(*evs) * MAX_EVENTS);

    if (!evs)
        oom("allocating events");

    int timeout = config.epoll_timeout;
    int events = 0;

    while ((events = epoll_wait(db->epollfd, evs, MAX_EVENTS, timeout)) > -1) {

        for (int i = 0; i < events; i++) {

            /* Check for errors first */
            if ((evs[i].events & EPOLLERR) ||
                    (evs[i].events & EPOLLHUP) ||
                    (!(evs[i].events & EPOLLIN) && !(evs[i].events & EPOLLOUT))) {

                /* An error has occured on this fd, or the socket is not
                   ready for reading */
                perror ("epoll_wait(2)");
                close(evs[i].data.fd);
                continue;
            } else if (evs[i].data.fd == config.run) {

                /* And quit event after that */
                eventfd_t val;
                eventfd_read(config.run, &val);

                DEBUG("Stopping epoll loop.");

                goto exit;
            } else {
                /* Finally handle the request according to its type */
                ((Client *) evs[i].data.ptr)->ctx_handler(db, evs[i].data.ptr);
            }
        }

        // Check for keys about to expire out
        expire_keys(db);
    }

exit:
    if (events == 0 && config.run == 0)
        perror("epoll_wait(2) error");

    free(evs);

    return NULL;
}

/*
 * Main entry point for start listening on a socket and running an epoll event
 * loop his main responsibility is to pass incoming client connections
 * descriptor to workers thread.
 */
int start_server(const char *addr, char *port, int node_fd) {

    /* Initialize config server object */
    config.loglevel = DEBUG;
    config.run = eventfd(0, EFD_NONBLOCK);
    config.epoll_timeout = 250;

    TriteDB tritedb;

    /* Initialize SizigyDB server object */
    tritedb.data = trie_new();
    tritedb.clients = list_init();
    tritedb.peers = list_init();
    tritedb.expiring_keys = list_init();

    /* Initialize epollfd for server component */
    const int epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        goto cleanup;
    }

    /* Initialize the sockets, first the server one */
    const int fd = make_listen(addr, port);

    /* Add eventfd to the loop, this time only in LT in order to wake up all threads */
    struct epoll_event ev;
    ev.data.fd = config.run;
    ev.events = EPOLLIN;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, config.run, &ev) < 0) {
        perror("epoll_ctl(2): add epollin");
    }

    /* Client structure for the server component */
    Client server = {
        .addr = addr,
        .fd = fd,
        .last_action_time = 0,
        .ctx_handler = accept_handler,
        .reply = NULL,
        .ptr = NULL
    };

    /* Set socket in EPOLLIN flag mode, ready to read data */
    add_epoll(epollfd, fd, &server);

    tritedb.epollfd = epollfd;

    INFO("TriteDB v0.1.0");
    INFO("Starting server on %s:%s", addr, port);

    run_server(&tritedb);

cleanup:
    /* Free all resources allocated */
    list_free(tritedb.peers, 1);
    trie_free(tritedb.data);

    for (ListNode *cursor = tritedb.clients->head; cursor; cursor = cursor->next) {
        Client *c = (Client *) cursor->data;
        free_client(&c);
    }

    list_free(tritedb.clients, 0);
    free_expiring_keys(tritedb.expiring_keys);

    DEBUG("Bye\n");
    return 0;
}
