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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include "list.h"
#include "util.h"
#include "server.h"
#include "config.h"
#include "ringbuf.h"
#include "network.h"
#include "protocol.h"


#define set_ack_reply(c, o) do {                        \
    Response *r = make_nocontent_response((o));         \
    Buffer *b = buffer_init(r->ncontent->header->size); \
    pack_response((b), r, NO_CONTENT);                  \
    set_reply((c), (b));                                \
    free_response(r, NO_CONTENT);                       \
} while (0)


struct informations info;


static void free_reply(Reply **);
static void free_client(Client **);
static int reply_handler(TriteDB *, Client *);
static int accept_handler(TriteDB *, Client *);
static int request_handler(TriteDB *, Client *);

// Commands
static int put_handler(TriteDB *, Client *);
static int get_handler(TriteDB *, Client *);
static int del_handler(TriteDB *, Client *);
static int ttl_handler(TriteDB *, Client *);
static int inc_handler(TriteDB *, Client *);
static int dec_handler(TriteDB *, Client *);
static int count_handler(TriteDB *, Client *);
static int keys_handler(TriteDB *, Client *);
static int info_handler(TriteDB *, Client *);
static int quit_handler(TriteDB *, Client *);

// Fixed size of the header of each packet, consists of essentially the first
// 5 bytes containing respectively the type of packet (PUT, GET, DEL etc ...)
// and the total length in bytes of the packet
static const int HEADLEN = sizeof(uint8_t) + sizeof(uint32_t);

/* Static command map, simple as it seems: OPCODE -> handler func */
static struct command commands_map[COMMAND_COUNT] = {
    {PUT, put_handler},
    {GET, get_handler},
    {DEL, del_handler},
    {TTL, ttl_handler},
    {INC, inc_handler},
    {DEC, dec_handler},
    {COUNT, count_handler},
    {KEYS, keys_handler},
    {INFO, info_handler},
    {QUIT, quit_handler}
};

/* Parse header, require at least the first 5 bytes in order to read packet
   type and total length that we need to recv to complete the packet */
Buffer *recv_packet(int clientfd, Ringbuffer *rbuf, uint8_t *opcode) {

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
    Reply *r = tmalloc(sizeof(*r));
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
    tfree(*r);
    *r = NULL;
}


static void free_client(Client **c) {
    if (!*c)
        return;
    if ((*c)->addr) {
        tfree((char *) (*c)->addr);
        (*c)->addr = NULL;
    }
    if ((*c)->reply) {
        free_reply(&(*c)->reply);
        (*c)->reply = NULL;
    }
    tfree(*c);
    *c = NULL;
}


static int quit_handler(TriteDB *db, Client *c) {

    tdebug("Closing connection with %s", c->addr);
    shutdown(c->fd, 0);
    close(c->fd);
    info.nclients--;
    del_epoll(db->epollfd, c->fd);

    free_request(c->ptr, EMPTY_COMMAND);
    // TODO clean up client list

    return -1;
}


static int info_handler(TriteDB *db, Client *c) {

    info.uptime = time(NULL) - info.start_time;
    // TODO make key-val-list response
    free_request(c->ptr, EMPTY_COMMAND);

    return OK;
}


static int keys_handler(TriteDB *db, Client *c) {

    KeyCommand *kc = ((Request *) c->ptr)->kcommand;

    List *keys = trie_prefix_find(db->data, (const char *) kc->key);

    Response *res = make_listcontent_response(keys);

    Buffer *b = buffer_init(res->lcontent->header->size);
    pack_response(b, res, LIST_CONTENT);

    tdebug("KEYS %d", b->size);

    set_reply(c, b);

    list_free(keys, 1);
    free_response(res, LIST_CONTENT);
    free_request(c->ptr, KEY_COMMAND);

    return OK;
}


static int put_handler(TriteDB *db, Client *c) {

    KeyValCommand *p = ((Request *) c->ptr)->kvcommand;
    clock_t start, end;
    double time_elapsed;

    int16_t ttl = p->ttl != 0 ? p->ttl : -NOTTL;

    // TODO refactor TTL insertion, investigate on bad-malloc_usable_size
    // issue
    if (p->is_prefix == 1) {
        start = clock();
        trie_prefix_set(db->data, (const char *) p->key, p->val, ttl);
        end = clock();
    } else {
        start = clock();
        trie_insert(db->data, (const char *) p->key, p->val, ttl);
        end = clock();

        // Update expiring keys if ttl != -NOTTL and sort it
        if (ttl != -NOTTL) {

            // XXX Find step to be removed
            void *val = NULL;

            // Check for key presence in the trie structure
            trie_find(db->data, (const char *) p->key, &val);

            struct NodeData *nd = val;
            nd->ttl = p->ttl;

            // It's a new TTL, so we update creation_time to now in order to
            // calculate the effective expiration of the key
            nd->ctime = nd->latime = (uint64_t) time(NULL);

            struct ExpiringKey *ek = tmalloc(sizeof(*ek));
            ek->nd = nd;
            ek->key = tstrdup((const char *) p->key);
            db->expiring_keys = list_push(db->expiring_keys, ek);

            // Sort in O(n) if there's more than one element in the list
            db->expiring_keys->head = merge_sort(db->expiring_keys->head);
        }
    }

    set_ack_reply(c, OK);

    time_elapsed = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000.0;

    tdebug("PUT %s -> %s in %f ms (s=%d m=%d)",
            p->key, p->val, time_elapsed, db->data->size, memory_used());

    free_request(c->ptr, KEY_VAL_COMMAND);

    return OK;
}


static int get_handler(TriteDB *db, Client *c) {

    KeyCommand *g = ((Request *) c->ptr)->kcommand;
    void *val = NULL;

    clock_t start, end;
    double time_elapsed;

    start = clock();

    // Test for the presence of the key in the trie structure
    bool found = trie_find(db->data, (const char *) g->key, &val);

    end = clock();

    // ms of execution
    time_elapsed = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000.0;

    if (found == false || val == NULL) {
        set_ack_reply(c, NOK);
        tdebug("GET %s -> not found (s=%d m=%d)",
                g->key, db->data->size, memory_used());
    } else {

        struct NodeData *nd = val;

        // If the key results expired, remove it instead of returning it
        int64_t now = time(NULL);
        int64_t delta = (nd->ctime + nd->ttl) - now;

        if (nd->ttl != -NOTTL && delta <= 0) {
            trie_delete(db->data, (const char *) g->key);
            set_ack_reply(c, NOK);
            tdebug("GET %s -> expired (s=%d m=%d)",
                    g->key, db->data->size, memory_used());
        } else {

            // Update the last access time
            nd->latime = time(NULL);

            // and return it
            Response *put = make_datacontent_response(nd->data);
            Buffer *b = buffer_init(put->dcontent->header->size);
            pack_response(b, put, DATA_CONTENT);

            tdebug("GET %s -> %s in %f ms (s=%d m=%d)",
                    g->key, nd->data, time_elapsed, db->data->size, memory_used());

            set_reply(c, b);
            free_response(put, DATA_CONTENT);
        }
    }
    free_request(c->ptr, KEY_COMMAND);

    return OK;
}


static int ttl_handler(TriteDB *db, Client *c) {

    KeyCommand *e = ((Request *) c->ptr)->kcommand;
    void *val = NULL;

    // Check for key presence in the trie structure
    bool found = trie_find(db->data, (const char *) e->key, &val);

    if (found == false || val == NULL) {
        set_ack_reply(c, NOK);
        tdebug("TTL %s -> not found (s=%d m=%d)",
                e->key, db->data->size, memory_used());
    } else {
        struct NodeData *nd = val;
        nd->ttl = e->ttl;

        // It's a new TTL, so we update creation_time to now in order to
        // calculate the effective expiration of the key
        nd->ctime = nd->latime = (uint64_t) time(NULL);
        struct ExpiringKey *ek = tmalloc(sizeof(*ek));
        ek->nd = nd;
        ek->key = tstrdup((const char *) e->key);

        // Push into the expiring keys list and merge sort it shortly after,
        // this way we have a mostly updated list of expiring keys at each
        // insert, making it simpler and more efficient to cycle through them
        // and remove it later.
        db->expiring_keys = list_push(db->expiring_keys, ek);
        db->expiring_keys->head = merge_sort(db->expiring_keys->head);

        set_ack_reply(c, NOK);
        tdebug("TTL %s -> %s set %d (s=%d m=%d)",
                e->key, nd->data, e->ttl, db->data->size, memory_used());
    }

    free_request(c->ptr, KEY_COMMAND);

    return OK;
}


static int del_handler(TriteDB *db, Client *c) {

    int code = OK;
    KeyListCommand *d = ((Request *) c->ptr)->klcommand;
    bool found = false;
    clock_t start, end;
    double time_elapsed;

    // Flush all data in case of no prefixes passed
    if (d->len == 0) {
        trie_node_free(db->data->root, &db->data->size);
    } else {
        for (int i = 0; i < d->len; i++) {

            // For each key in the keys array, check for presence and try to
            // remove it, if the `is_prefix` flag is a set the key will be
            // treated as a prefix wildcard (*) and we'll remove all keys below
            // it in the trie
            if (d->keys[i]->is_prefix == 1) {

                start = clock();

                // We are dealing with a wildcard, so we apply the deletion to
                // all keys below the wildcard
                trie_prefix_delete(db->data, (const char *) d->keys[i]->key);

                end = clock();

                // ms of execution
                time_elapsed = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000.0;
                tdebug("DEL prefix %s in %d ms (s=%d m=%d)",
                        d->keys[i]->key, time_elapsed, memory_used());
            } else {
                found = trie_delete(db->data, (const char *) d->keys[i]->key);
                if (found == false) {
                    code = NOK;
                    tdebug("DEL %s failed (s=%d m=%d)",
                            d->keys[i]->key, db->data->size, memory_used());
                } else {
                    tdebug("DEL %s (s=%d m=%d)",
                            d->keys[i]->key, db->data->size, memory_used());
                }
            }
        }
    }

    set_ack_reply(c, code);
    free_request(c->ptr, KEY_LIST_COMMAND);

    return OK;
}

/* Increment an integer value by 1. If the string value doesn't contain a
   proper integer return a NOK.

   XXX check for bounds */
static int inc_handler(TriteDB *db, Client *c) {

    int code = OK, n = 0;
    KeyListCommand *inc = ((Request *) c->ptr)->klcommand;
    bool found = false;
    void *val = NULL;

    for (int i = 0; i < inc->len; i++) {

        if (inc->keys[i]->is_prefix) {
            trie_prefix_inc(db->data, (const char *) inc->keys[i]->key);
            tdebug("INC %s (s=%d m=%d)",
                    inc->keys[i]->key, db->data->size, memory_used());
        } else {
            // For each key in the keys array, check for presence and increment it
            // by one
            found = trie_find(db->data, (const char *) inc->keys[i]->key, &val);
            if (found == false || !val) {
                code = NOK;
                tdebug("INC %s failed (s=%d m=%d)",
                        inc->keys[i]->key, db->data->size, memory_used());
            } else {
                struct NodeData *nd = val;
                if (!is_integer(nd->data)) {
                    code = NOK;
                    tdebug("INC %s failed, not an integer value (s=%d m=%d)",
                            inc->keys[i]->key, db->data->size, memory_used());
                } else {
                    n = parse_int(nd->data);
                    ++n;
                    // Check for realloc if the new value is "larger" then previous
                    char tmp[12];  // max size in bytes
                    sprintf(tmp, "%d", n);  // XXX Unsafe
                    size_t len = strlen(tmp);
                    nd->data = trealloc(nd->data, len + 1);
                    strncpy(nd->data, tmp, len + 1);
                    tdebug("INC %s (s=%d m=%d)",
                            inc->keys[i]->key, db->data->size, memory_used());
                }
            }
        }
    }

    set_ack_reply(c, code);
    free_request(c->ptr, KEY_LIST_COMMAND);

    return OK;
}

/* Decrement an integer value by 1. If the string value doesn't contain a
   proper integer return a NOK.

   XXX check for bounds */
static int dec_handler(TriteDB *db, Client *c) {

    int code = OK, n = 0;
    KeyListCommand *dec = ((Request *) c->ptr)->klcommand;
    bool found = false;
    void *val = NULL;

    for (int i = 0; i < dec->len; i++) {

        if (dec->keys[i]->is_prefix) {
            trie_prefix_dec(db->data, (const char *) dec->keys[i]->key);
            tdebug("DEC %s (s=%d m=%d)",
                    dec->keys[i]->key, db->data->size, memory_used());
        } else {

            // For each key in the keys array, check for presence and increment it
            // by one
            found = trie_find(db->data, (const char *) dec->keys[i]->key, &val);
            if (found == false || !val) {
                code = NOK;
                tdebug("DEC %s failed (s=%d m=%d)",
                        dec->keys[i]->key, db->data->size, memory_used());
            } else {
                struct NodeData *nd = val;
                if (!is_integer(nd->data)) {
                    code = NOK;
                    tdebug("DEC %s failed, not an integer value (s=%d m=%d)",
                            dec->keys[i]->key, db->data->size, memory_used());
                } else {
                    n = parse_int(nd->data);
                    --n;
                    // Check for realloc if the new value is "smaller" then previous
                    char tmp[12];
                    sprintf(tmp, "%d", n);
                    size_t len = strlen(tmp);
                    nd->data = trealloc(nd->data, len + 1);
                    strncpy(nd->data, tmp, len + 1);
                    tdebug("DEC %s (s=%d m=%d)",
                            dec->keys[i]->key, db->data->size, memory_used());
                }
            }
        }
    }

    set_ack_reply(c, code);
    free_request(c->ptr, KEY_LIST_COMMAND);

    return OK;
}


static int count_handler(TriteDB *db, Client *c) {

    int count = 0;
    KeyCommand *cnt = ((Request *) c->ptr)->kcommand;
    clock_t start, end;
    double time_elapsed;

    if (!cnt->key) {

        // Get size of the entire trie
        tdebug("COUNT %d (s=%d m=%d)",
                db->data->size, db->data->size, memory_used());
        count = db->data->size;

    } else {

        start = clock();

        // Get the size of each key below the requested one, glob operation
        count = trie_prefix_count(db->data, (const char *) cnt->key);
        end = clock();

        // ms of execution
        time_elapsed = (((double) (end - start)) / CLOCKS_PER_SEC) * 1000.0;
        tdebug("COUNT %d in %f ms (s=%d m=%d)",
                count, time_elapsed, db->data->size, memory_used());
    }

    Response *res = make_valuecontent_response(count);
    Buffer *b = buffer_init(res->vcontent->header->size);
    pack_response(b, res, VALUE_CONTENT);
    set_reply(c, b);
    free_response(res, VALUE_CONTENT);

    free_request(c->ptr, KEY_COMMAND);

    return OK;
}


/* Handle incoming requests, after being accepted or after a reply */
static int request_handler(TriteDB *db, Client *client) {

    int clientfd = client->fd;

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

    Request *pkt = unpack_request(opcode, b);

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
    int dc = 0;

    // Loop through commands_hashmap array to find the correct handler
    for (int i = 0; i < COMMAND_COUNT; i++) {
        if (commands_map[i].ctype == opcode) {
            dc = commands_map[i].handler(db, client);
            executed = 1;
        }
    }

    // Record request on the counter
    info.nrequests++;

    // If no handler is found, it must be an error case
    if (executed == 0)
        terror("Unknown command");

    if (dc == -1)
        return 0;

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

    int fd = server->fd;

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
    Client *client = tmalloc(sizeof(Client));
    if (!client) oom("creating client during accept");

    client->addr = tstrdup(ip_buff);
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

    /* Record the new client connected */
    info.nclients++;
    info.nconnections++;

    return 0;
}


static int compare_node(void *arg1, void *arg2) {

    struct ExpiringKey *ek1 = ((ListNode *) arg1)->data;
    struct ExpiringKey *ek2 = ((ListNode *) arg2)->data;

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
                if (ek->key) tfree((char *) ek->key);
                tfree(ek);
            }
            tfree(h);
        }

        h = tmp;
    }

    // free List structure pointer
    tfree(ekeys);
}

/* Cycle through sorted list of expiring keys and remove those which are
   elegible */
static void expire_keys(TriteDB *db) {

    if (db->expiring_keys->len <= 0)
        return;

    int64_t now = (int64_t) time(NULL);
    int64_t delta = 0LL;
    struct ExpiringKey *ek = NULL;

    for (ListNode *n = db->expiring_keys->head; n != NULL
            && db->expiring_keys->len > 0; n = n->next) {

        ek = n->data;

        // Calculate deltaT between creation time + TTL and now
        delta = (ek->nd->ctime + ek->nd->ttl) - now;

        // We can exit the loop at the fist unexpired key as they are
        // already ordered by remaining expiration seconds
        if (delta > 0)
            break;

        // Expired keys must be removed
        trie_delete(db->data, ek->key);
        ListNode delnode = { ek, NULL };

        // Updating expiring keys list
        if (n == db->expiring_keys->head) {
            list_remove(db->expiring_keys, &delnode, compare_node);
            n = db->expiring_keys->head;
        } else {
            list_remove(db->expiring_keys, &delnode, compare_node);
        }

        tdebug("EXPIRING %s (s=%d m=%d)",
                ek->key, db->data->size, memory_used());

        tfree((char *) ek->key);
        tfree(ek);
        ek = NULL;

        if (!db->expiring_keys->head || !db->expiring_keys->head->next)
            break;
    }

    // Re-sort remaining keys, if any
    db->expiring_keys->head = merge_sort(db->expiring_keys->head);
}

/* Main worker function, his responsibility is to wait on events on a shared
   EPOLL fd, use the same way for clients or peer to distribute messages */
static void *run_server(TriteDB *db) {

    struct epoll_event *evs = tmalloc(sizeof(*evs) * MAX_EVENTS);

    if (!evs)
        oom("allocating events");

    int timeout = config.epoll_timeout;
    int events = 0;

    struct itimerspec timervalue;

    int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

    memset(&timervalue, 0x00, sizeof(timervalue));

    timervalue.it_value.tv_sec = 0;
    timervalue.it_value.tv_nsec = TTL_CHECK_INTERVAL;
    timervalue.it_interval.tv_sec = 0;
    timervalue.it_interval.tv_nsec = TTL_CHECK_INTERVAL;

    if (timerfd_settime(timerfd, 0, &timervalue, NULL) < 0) {
        perror("timerfd_settime");
    }

    // Add the timer to the event loop
    struct epoll_event ev;
    ev.data.fd = timerfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(db->epollfd, EPOLL_CTL_ADD, timerfd, &ev) < 0)
        perror("epoll_ctl(2): EPOLLIN");

    long int timers = 0;

    while (1) {

        events = epoll_wait(db->epollfd, evs, MAX_EVENTS, timeout);

        if (events < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        for (int i = 0; i < events; i++) {

            /* Check for errors first */
            if ((evs[i].events & EPOLLERR) ||
                    (evs[i].events & EPOLLHUP) ||
                    (!(evs[i].events & EPOLLIN) && !(evs[i].events & EPOLLOUT))) {

                /* An error has occured on this fd, or the socket is not
                   ready for reading */
                perror("epoll_wait(2)");
                close(evs[i].data.fd);
                continue;
            } else if (evs[i].data.fd == config.run) {

                /* And quit event after that */
                eventfd_t val;
                eventfd_read(config.run, &val);

                tdebug("Stopping epoll loop.");

                goto exit;

            } else if (evs[i].data.fd == timerfd) {
                (void) read(evs[i].data.fd, &timers, 8);
                // Check for keys about to expire out
                expire_keys(db);
            } else {
                /* Finally handle the request according to its type */
                ((Client *) evs[i].data.ptr)->ctx_handler(db, evs[i].data.ptr);
            }
        }
    }

exit:

    if (events <= 0 && config.run != 1)
        perror("epoll_wait(2) error");

    tfree(evs);

    return NULL;
}

/*
 * Main entry point for start listening on a socket and running an epoll event
 * loop his main responsibility is to pass incoming client connections
 * descriptor to workers thread.
 * In this case there's no threads and uses just a single thread with
 * multiplexing I/O, but it's trivial to transform the main run_server routine
 * into a thread worker and launch some more (e.g. one per CPU core).
 *
 * Accepts two mandatory string arguments, addr and port, in case of UNIX
 * domain socket, addr represents the path on the FS where the socket fd is
 * located, port will be ignored.
 */
int start_server(const char *addr, const char *port, int node_fd) {

    /* Main datastore reference */
    TriteDB tritedb;

    /* Initialize SizigyDB server object */
    tritedb.data = trie_new();
    tritedb.clients = list_init();
    tritedb.peers = list_init();
    tritedb.expiring_keys = list_init();

    /* Initialize epollfd for server component */
    int epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        goto cleanup;
    }

    /* Initialize the sockets, first the server one */
    int fd = make_listen(addr, port, config.socket_family);

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

    tinfo("TriteDB v%s", config.version);
    if (config.socket_family == UNIX)
        tinfo("Starting server on %s", addr);
    else
        tinfo("Starting server on %s:%s", addr, port);

    // Record start time
    info.start_time = time(NULL);

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

    t_log_close();

    tdebug("Bye\n");
    return 0;
}
