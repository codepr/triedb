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
#include <uuid/uuid.h>
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


static void free_reply(Reply *);
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
static int use_handler(TriteDB *, Client *);
static int db_handler(TriteDB *, Client *);
static int count_handler(TriteDB *, Client *);
static int keys_handler(TriteDB *, Client *);
static int info_handler(TriteDB *, Client *);
static int quit_handler(TriteDB *, Client *);

// Fixed size of the header of each packet, consists of essentially the first
// 6 bytes containing respectively the type of packet (PUT, GET, DEL etc ...)
// the total length in bytes of the packet and the is_bulk flag which tell if
// the packet contains a stream of commands or a single one
static const int HEADLEN = (2 * sizeof(uint8_t)) + sizeof(uint32_t);

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
    {USE, use_handler},
    {DB, db_handler},
    {INFO, info_handler},
    {QUIT, quit_handler}
};

/* Parse header, require at least the first 5 bytes in order to read packet
   type and total length that we need to recv to complete the packet */
Buffer *recv_packet(int clientfd, Ringbuffer *rbuf, uint8_t *opcode, int *rc) {

    size_t n = 0;
    uint8_t read_all = 0;

    while (n < HEADLEN) {
        /* Read first 6 bytes to get the total len of the packet */
        n += recvbytes(clientfd, rbuf, read_all, HEADLEN);
        if (n <= 0) {
            *rc = -ERRCLIENTDC;
            return NULL;
        }
    }

    uint8_t *tmp = tmalloc(ringbuf_size(rbuf));
    uint8_t *bytearray = tmp;

    /* Try to read at least length of the packet */
    for (uint8_t i = 0; i < HEADLEN; i++)
        ringbuf_pop(rbuf, bytearray++);

    /* Read opcode, the first byte of every packet */
    uint8_t *opc = (uint8_t *) tmp;

    /* If opcode is not known close the connection */
    bool ok = false;
    for (int i = 0; i < COMMAND_COUNT; i++)
        if (*opc == commands_map[i].ctype)
            ok = true;

    if (!ok)
        goto errrecv;

    /* Read the total length of the packet */
    uint32_t tlen = ntohl(*((uint32_t *) (tmp + sizeof(uint8_t))));

    /* Set return code to -ERRMAXREQSIZE in case of total packet len exceed
       the configuration limit `max_request_size` */
    if (tlen > config.max_request_size) {
        *rc = -ERRMAXREQSIZE;
        goto err;
    }

    /* Read remaining bytes to complete the packet */
    while (ringbuf_size(rbuf) < tlen - HEADLEN)
        if ((n = recvbytes(clientfd, rbuf, read_all, tlen - HEADLEN)) < 0)
            goto errrecv;

    /* Allocate a buffer to fit the entire packet */
    Buffer *b = buffer_init(tlen);

    /* Copy previous read part of the header (first 6 bytes) */
    memcpy(b->data, tmp, HEADLEN);

    /* Move forward pointer after HEADLEN bytes */
    bytearray = b->data + HEADLEN;

    /* Empty the rest of the ring buffer */
    while ((tlen - HEADLEN) > 0) {
        ringbuf_pop(rbuf, bytearray++);
        --tlen;
    }

    *opcode = *opc;

    tfree(tmp);

    return b;

errrecv:

    shutdown(clientfd, 0);
    close(clientfd);

err:

    tfree(tmp);

    return NULL;
}

/* Build a reply object and link it to the Client pointer */
static void set_reply(Client *c, Buffer *payload) {

    Reply *r = tmalloc(sizeof(*r));

    if (!r)
        oom("setting reply");

    r->fd = c->fd;
    r->payload = payload;

    c->reply = r;
}


static void free_reply(Reply *r) {

    if (!r)
        return;

    if (r->payload)
        buffer_destroy(r->payload);

    tfree(r);
}

/* Hashtable destructor function for Client objects. */
static int client_free(HashTableEntry *entry) {

    if (!entry)
        return -HASHTABLE_ERR;

    Client *c = entry->val;

    if (!c)
        return -HASHTABLE_ERR;

    if (c->addr)
        tfree((char *) c->addr);

    if (c->reply)
        free_reply(c->reply);

    tfree(c);

    return HASHTABLE_OK;
}

/* Hashtable destructor function for Database objects. */
static int database_free(HashTableEntry *entry) {

    if (!entry)
        return -HASHTABLE_ERR;

    tfree((char *) ((Database *) entry->val)->name);

    trie_free(((Database *) entry->val)->data);

    tfree(entry->val);
    tfree((char *) entry->key);

    return HASHTABLE_OK;
}


/********************************/
/*      COMMAND HANDLERS        */
/********************************/


static int quit_handler(TriteDB *db, Client *c) {

    tdebug("Closing connection with %s", c->addr);
    del_epoll(db->epollfd, c->fd);
    shutdown(c->fd, 0);
    close(c->fd);
    info.nclients--;

    free_request(c->ptr, SINGLE_REQUEST);

    // Remove client from the clients map
    hashtable_del(db->clients, c->uuid);

    return -1;
}


static int info_handler(TriteDB *db, Client *c) {

    info.uptime = time(NULL) - info.start_time;
    // TODO make key-val-list response
    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}


static int keys_handler(TriteDB *db, Client *c) {

    KeyCommand *cmd = ((Request *) c->ptr)->command->kcommand;

    List *keys = trie_prefix_find(c->db->data, (const char *) cmd->key);

    Response *response = make_listcontent_response(keys);

    Buffer *buffer = buffer_init(response->lcontent->header->size);
    pack_response(buffer, response, LIST_CONTENT);

    set_reply(c, buffer);

    list_free(keys, 1);
    free_response(response, LIST_CONTENT);
    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}


static bool compare_ttl(void *arg1, void *arg2) {

    uint64_t now = time(NULL);

    /* cast to cluster_node */
    const struct NodeData *n1 = ((struct ExpiringKey *) arg1)->nd;
    const struct NodeData *n2 = ((struct ExpiringKey *) arg2)->nd;

    uint64_t delta_l1 = (n1->ctime + n1->ttl) - now;
    uint64_t delta_l2 = (n2->ctime + n2->ttl) - now;

    return delta_l1 <= delta_l2;
}

/* Private function, insert or update values into the the trie database,
   updating, if any present, expiring keys vector */
static void put_data_into_trie(TriteDB *tdb, Database *db, KeyValCommand *cmd) {

    int16_t ttl = cmd->ttl != 0 ? cmd->ttl : -NOTTL;

    // TODO refactor TTL insertion, investigate on bad-malloc_usable_size
    // issue
    if (cmd->is_prefix == 1) {
        trie_prefix_set(db->data, (const char *) cmd->key, cmd->val, ttl);
    } else {
        struct NodeData *nd =
            trie_insert(db->data, (const char *) cmd->key, cmd->val);

        bool has_ttl = nd->ttl == -NOTTL ? false : true;

        // Update expiring keys if ttl != -NOTTL and sort it
        if (ttl != -NOTTL) {

            nd->ttl = cmd->ttl;

            // It's a new TTL, so we update creation_time to now in order
            // to calculate the effective expiration of the key
            nd->ctime = nd->latime = (uint64_t) time(NULL);

            // Create a data strucuture to handle expiration
            struct ExpiringKey *ek = tmalloc(sizeof(*ek));
            ek->nd = nd;
            ek->key = tstrdup((const char *) cmd->key);
            ek->data_ptr = db->data;

            // Add the node data to the expiring keys only if it wasn't
            // already in, otherwise nothing should change cause the
            // expiring keys already got a pointer to the node data, which
            // will now have an updated TTL value
            if (!has_ttl)
                vector_append(tdb->expiring_keys, ek);

            // Quicksort in O(nlogn) if there's more than one element in
            // the vector
            vector_qsort(tdb->expiring_keys,
                    compare_ttl, sizeof(struct ExpiringKey));
        }

        // Update total counter of keys
        tdb->keyspace_size++;
    }
}


static int put_handler(TriteDB *db, Client *c) {

    Request *request = c->ptr;

    if (request->reqtype == SINGLE_REQUEST) {

        KeyValCommand *cmd = request->command->kvcommand;

        // Insert data into the trie
        put_data_into_trie(db, c->db, cmd);

    } else {

        BulkCommand *bcmd = request->bulk_command;

        // Apply insertion for each command
        for (uint32_t i = 0; i < bcmd->ncommands; i++)
            put_data_into_trie(db, c->db, bcmd->commands[i]->kvcommand);
    }

    // For now just a single response
    set_ack_reply(c, OK);

    free_request(c->ptr, request->reqtype);

    return OK;
}


static int get_handler(TriteDB *db, Client *c) {

    KeyCommand *cmd = ((Request *) c->ptr)->command->kcommand;
    void *val = NULL;

    // Test for the presence of the key in the trie structure
    bool found = trie_find(c->db->data, (const char *) cmd->key, &val);

    if (found == false || val == NULL) {
        set_ack_reply(c, NOK);
    } else {

        struct NodeData *nd = val;

        // If the key results expired, remove it instead of returning it
        int64_t now = time(NULL);
        int64_t delta = (nd->ctime + nd->ttl) - now;

        if (nd->ttl != -NOTTL && delta <= 0) {
            trie_delete(c->db->data, (const char *) cmd->key);
            set_ack_reply(c, NOK);
            // Update total keyspace counter
            db->keyspace_size--;
        } else {

            // Update the last access time
            nd->latime = time(NULL);

            // and return it
            Response *response = make_datacontent_response(nd->data);
            Buffer *buffer = buffer_init(response->dcontent->header->size);
            pack_response(buffer, response, DATA_CONTENT);

            set_reply(c, buffer);
            free_response(response, DATA_CONTENT);
        }
    }

    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}


static int ttl_handler(TriteDB *db, Client *c) {

    KeyCommand *cmd = ((Request *) c->ptr)->command->kcommand;
    void *val = NULL;

    // Check for key presence in the trie structure
    bool found = trie_find(c->db->data, (const char *) cmd->key, &val);

    if (found == false || val == NULL) {
        set_ack_reply(c, NOK);
    } else {
        struct NodeData *nd = val;
        bool has_ttl = nd->ttl == -NOTTL ? false : true;
        nd->ttl = cmd->ttl;

        // It's a new TTL, so we update creation_time to now in order to
        // calculate the effective expiration of the key
        nd->ctime = nd->latime = (uint64_t) time(NULL);
        struct ExpiringKey *ek = tmalloc(sizeof(*ek));
        ek->nd = nd;
        ek->key = tstrdup((const char *) cmd->key);
        ek->data_ptr = c->db->data;

        // Push into the expiring keys list and merge sort it shortly after,
        // this way we have a mostly updated list of expiring keys at each
        // insert, making it simpler and more efficient to cycle through them
        // and remove it later.
        if (!has_ttl)
            vector_append(db->expiring_keys, ek);

        vector_qsort(db->expiring_keys, compare_ttl, sizeof(struct ExpiringKey));

        set_ack_reply(c, OK);
    }

    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}


static int del_handler(TriteDB *db, Client *c) {

    int code = OK;
    KeyListCommand *cmd = ((Request *) c->ptr)->command->klcommand;
    bool found = false;

    // Flush all data in case of no prefixes passed
    if (cmd->len == 0) {
        trie_node_free(c->db->data->root, &c->db->data->size);
        // Update total keyspace counter
        db->keyspace_size--;
    } else {
        size_t currsize = 0;
        for (int i = 0; i < cmd->len; i++) {

            // For each key in the keys array, check for presence and try to
            // remove it, if the `is_prefix` flag is a set the key will be
            // treated as a prefix wildcard (*) and we'll remove all keys below
            // it in the trie
            if (cmd->keys[i]->is_prefix == 1) {

                currsize = c->db->data->size;
                // We are dealing with a wildcard, so we apply the deletion to
                // all keys below the wildcard
                trie_prefix_delete(c->db->data, (const char *) cmd->keys[i]->key);
                // Update total keyspace counter
                db->keyspace_size -= currsize - c->db->data->size;
            } else {
                found = trie_delete(c->db->data, (const char *) cmd->keys[i]->key);
                if (found == false)
                    code = NOK;
                // Update total keyspace counter
                db->keyspace_size--;
            }
        }
    }

    set_ack_reply(c, code);
    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}

/* Increment an integer value by 1. If the string value doesn't contain a
   proper integer return a NOK.

   XXX check for bounds */
static int inc_handler(TriteDB *db, Client *c) {

    int code = OK, n = 0;
    KeyListCommand *inc = ((Request *) c->ptr)->command->klcommand;
    bool found = false;
    void *val = NULL;

    for (int i = 0; i < inc->len; i++) {

        if (inc->keys[i]->is_prefix == 1) {
            trie_prefix_inc(c->db->data, (const char *) inc->keys[i]->key);
        } else {
            // For each key in the keys array, check for presence and increment it
            // by one
            found = trie_find(c->db->data,
                    (const char *) inc->keys[i]->key, &val);
            if (found == false || !val) {
                code = NOK;
            } else {
                struct NodeData *nd = val;
                if (!is_integer(nd->data)) {
                    code = NOK;
                } else {
                    n = parse_int(nd->data);
                    ++n;
                    // Check for realloc if the new value is "larger" then previous
                    char tmp[number_len(n)];  // max size in bytes
                    sprintf(tmp, "%d", n);  // XXX Unsafe
                    size_t len = strlen(tmp);
                    nd->data = trealloc(nd->data, len + 1);
                    strncpy(nd->data, tmp, len + 1);
                }
            }
        }
    }

    set_ack_reply(c, code);
    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}

/* Decrement an integer value by 1. If the string value doesn't contain a
   proper integer return a NOK.

   XXX check for bounds */
static int dec_handler(TriteDB *db, Client *c) {

    int code = OK, n = 0;
    KeyListCommand *dec = ((Request *) c->ptr)->command->klcommand;
    bool found = false;
    void *val = NULL;

    for (int i = 0; i < dec->len; i++) {

        if (dec->keys[i]->is_prefix) {
            trie_prefix_dec(c->db->data, (const char *) dec->keys[i]->key);
        } else {

            // For each key in the keys array, check for presence and increment it
            // by one
            found = trie_find(c->db->data,
                    (const char *) dec->keys[i]->key, &val);
            if (found == false || !val) {
                code = NOK;
            } else {
                struct NodeData *nd = val;
                if (!is_integer(nd->data)) {
                    code = NOK;
                } else {
                    n = parse_int(nd->data);
                    --n;
                    // Check for realloc if the new value is "smaller" then previous
                    char tmp[number_len(n)];
                    sprintf(tmp, "%d", n);
                    size_t len = strlen(tmp);
                    nd->data = trealloc(nd->data, len + 1);
                    strncpy(nd->data, tmp, len + 1);
                }
            }
        }
    }

    set_ack_reply(c, code);
    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}

/* Get the current selected DB of the requesting client */
static int db_handler(TriteDB *db, Client *c) {

    Response *response = make_datacontent_response((uint8_t *) c->db->name);
    Buffer *buffer = buffer_init(response->dcontent->header->size);
    pack_response(buffer, response, DATA_CONTENT);

    set_reply(c, buffer);
    free_response(response, DATA_CONTENT);

    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}

/* Set the current selected namespace for the connected client. */
static int use_handler(TriteDB *db, Client *c) {

    KeyCommand *cmd = ((Request *) c->ptr)->command->kcommand;

    /* Check for presence first */
    Database *database = hashtable_get(db->dbs, (const char *) cmd->key);

    /* It doesn't exist, we create a new database with the given name,
       otherwise just assign it to the current db of the client */
    if (!database) {
        // TODO check for OOM
        database = tmalloc(sizeof(*database));
        database->name = tstrdup((const char *) cmd->key);
        database->data = trie_new();
        // Add it to the databases table
        hashtable_put(db->dbs, tstrdup(database->name), database);
        c->db = database;
    } else {
        c->db = database;
    }

    set_ack_reply(c, OK);

    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}


static int count_handler(TriteDB *db, Client *c) {

    int count = 0;
    KeyCommand *cnt = ((Request *) c->ptr)->command->kcommand;

    // Get the size of each key below the requested one, glob operation or the
    // entire trie size in case of NULL key
    count = !cnt->key ? c->db->data->size :
        trie_prefix_count(c->db->data, (const char *) cnt->key);

    Response *res = make_valuecontent_response(count);
    Buffer *b = buffer_init(res->vcontent->header->size);
    pack_response(b, res, VALUE_CONTENT);
    set_reply(c, b);
    free_response(res, VALUE_CONTENT);

    free_request(c->ptr, SINGLE_REQUEST);

    return OK;
}


/**************************************/
/*          SERVER_HANDLERS           */
/**************************************/


/* Handle incoming requests, after being accepted or after a reply */
static int request_handler(TriteDB *db, Client *client) {

    int clientfd = client->fd;

    /* Buffer to initialize the ring buffer, used to handle input from client */
    uint8_t *buffer = tmalloc(config.max_request_size);

    /* Ringbuffer pointer struct, helpful to handle different and unknown
       size of chunks of data which can result in partially formed packets or
       overlapping as well */
    Ringbuffer *rbuf = ringbuf_init(buffer, config.max_request_size);

    /* Placeholders structures, at this point we still don't know if we got a
       request or a response */
    uint8_t opcode = 0;
    int rc = 0;

    /* We must read all incoming bytes till an entire packet is received. This
       is achieved by using a standardized protocol, which send the size of the
       complete packet as the first 4 bytes. By knowing it we know if the
       packet is ready to be deserialized and used. */
    Buffer *b = recv_packet(clientfd, rbuf, &opcode, &rc);

    /* Looks like we got a client disconnection.
       TODO: Set a error_handler for ERRMAXREQSIZE instead of dropping client
             connection, explicitly returning an informative error code to the
             client connected. */
    if (rc == -ERRCLIENTDC || rc == -ERRMAXREQSIZE) {
        ringbuf_free(rbuf);
        tfree(buffer);
        goto errclient;
    }

    /* If not correct packet received, we must free ringbuffer and reset the
       handler to the request again, setting EPOLL to EPOLLIN */
    if (!b)
        goto freebuf;

    /* Currently we have a stream of bytes, we want to unpack them into a
       Request structure */
    Request *pkt = unpack_request(b);

    /* No more need of the byte buffer from now on */
    buffer_destroy(b);

    /* Free ring buffer as we alredy have all needed informations in memory */
    ringbuf_free(rbuf);

    tfree(buffer);

    /* If the packet couldn't be unpacket (e.g. we're OOM) we close the
       connection and release the client */
    if (!pkt)
        goto errclient;

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
        goto reset;

    /* A disconnection happened, we close the handler, the file descriptor
       have been already removed from the event loop */
    if (dc == -1)
        goto exit;

    // Set reply handler as the current context handler
    client->ctx_handler = reply_handler;

    /* Reset handler to request_handler in order to read new incoming data and
       EPOLL event for read fds */
    mod_epoll(db->epollfd, clientfd, EPOLLOUT, client);

exit:

    return 0;

freebuf:

    ringbuf_free(rbuf);
    tfree(buffer);

reset:

    client->ctx_handler = request_handler;
    mod_epoll(db->epollfd, clientfd, EPOLLIN, client);
    return 0;

errclient:

    terror("Dropping client on %s", client->addr);
    shutdown(client->fd, 0);
    close(client->fd);
    hashtable_del(db->clients, client->uuid);
    info.nclients--;
    return -1;
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

    free_reply(client->reply);
    client->reply = NULL;

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

    /* Just some informations retrieval of the new accepted client connection */
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

    /* Create a client structure to handle his context connection */
    Client *client = tmalloc(sizeof(Client));
    if (!client)
        oom("creating client during accept");

    /* Generate random uuid */
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    uuid_unparse(binuuid, (char *) client->uuid);

    /* Populate client structure */
    client->addr = tstrdup(ip_buff);
    client->fd = clientsock;
    client->ctx_handler = request_handler;

    /* Record last action as of now */
    client->last_action_time = (uint64_t) time(NULL);

    client->reply = NULL;

    /* Set the default db for the current user */
    client->db = hashtable_get(db->dbs, "db0");

    /* Add it to the db instance */
    hashtable_put(db->clients, client->uuid, client);

    /* Add it to the epoll loop */
    add_epoll(db->epollfd, clientsock, client);

    /* Rearm server fd to accept new connections */
    mod_epoll(db->epollfd, fd, EPOLLIN, server);

    /* Record the new client connected */
    info.nclients++;
    info.nconnections++;

    return 0;
}


static void free_expiring_keys(Vector *ekeys) {

    if (!ekeys)
        return;

    struct ExpiringKey *ek = NULL;

    for (int i = 0; i < ekeys->size; i++) {

        ek = vector_get(ekeys, i);

        if (!ek)
            continue;

        if (ek->key)
            tfree((char *) ek->key);

        tfree(ek);
    }

    // free vector structure pointer
    tfree(ekeys->items);
    tfree(ekeys);
}

/* Cycle through sorted list of expiring keys and remove those which are
   elegible */
static void expire_keys(TriteDB *db) {

    if (db->expiring_keys->size == 0)
        return;

    int64_t now = (int64_t) time(NULL);
    int64_t delta = 0LL;
    struct ExpiringKey *ek = NULL;

    for (int i = 0; i < db->expiring_keys->size; i++) {

        ek = vector_get(db->expiring_keys, i);
        delta = (ek->nd->ctime + ek->nd->ttl) - now;

        if (delta > 0)
            break;

        /* ek->data_ptr points to the trie of the client which stores the given
           key */
        trie_delete(ek->data_ptr, ek->key);

        vector_delete(db->expiring_keys, i);

        // Update total keyspace counter
        db->keyspace_size--;

        tdebug("EXPIRING %s", ek->key);

        tfree((char *) ek->key);
        tfree(ek);
        ek = NULL;
    }
}

/* Print and log some basic stats */
void log_stats(TriteDB *db) {
    info.uptime = time(NULL) - info.start_time;
    const char *uptime = time_to_string(info.uptime);
    const char *memory = memory_to_string(memory_used());
    tdebug("Connected clients: %d total connections: %d "
            "requests: %d dbs: %ld keys: %ld memory usage: %s  uptime: %s",
            info.nclients, info.nconnections, info.nrequests, db->dbs->size,
            db->keyspace_size, memory, uptime);
    tfree((char *) uptime);
    tfree((char *) memory);
}

/* Temporary auxiliary function till the network::epoll_loop is ready, add a
   periodic task to the epoll loop */
static int add_cron_task(int epollfd, struct itimerspec timervalue) {

    int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);

    if (timerfd_settime(timerfd, 0, &timervalue, NULL) < 0)
        perror("timerfd_settime");

    // Add the timer to the event loop
    struct epoll_event ev;
    ev.data.fd = timerfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, timerfd, &ev) < 0) {
        perror("epoll_ctl(2): EPOLLIN");
        return -1;
    }

    return timerfd;
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

    memset(&timervalue, 0x00, sizeof(timervalue));

    timervalue.it_value.tv_sec = 0;
    timervalue.it_value.tv_nsec = TTL_CHECK_INTERVAL;
    timervalue.it_interval.tv_sec = 0;
    timervalue.it_interval.tv_nsec = TTL_CHECK_INTERVAL;

    // add expiration keys cron task
    int exptimerfd = add_cron_task(db->epollfd, timervalue);

    int statstimerfd = -1;
    if (config.loglevel == DEBUG) {
        struct itimerspec st_timervalue;

        memset(&timervalue, 0x00, sizeof(st_timervalue));

        st_timervalue.it_value.tv_sec = STATS_PRINT_INTERVAL;
        st_timervalue.it_value.tv_nsec = 0;
        st_timervalue.it_interval.tv_sec = STATS_PRINT_INTERVAL;
        st_timervalue.it_interval.tv_nsec = 0;

        statstimerfd = add_cron_task(db->epollfd, st_timervalue);
    }

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
                terror("Dropping client on %s",
                        ((Client *) evs[i].data.ptr)->addr);
                hashtable_del(db->clients, ((Client *) evs[i].data.ptr)->uuid);
                info.nclients--;
                close(evs[i].data.fd);

                continue;

            } else if (evs[i].data.fd == config.run) {

                /* And quit event after that */
                eventfd_t val;
                eventfd_read(config.run, &val);

                tdebug("Stopping epoll loop.");

                goto exit;

            } else if (exptimerfd != -1 && evs[i].data.fd == exptimerfd) {
                (void) read(evs[i].data.fd, &timers, 8);
                // Check for keys about to expire out
                expire_keys(db);
            } else if (statstimerfd != -1 && evs[i].data.fd == statstimerfd) {
                (void) read(evs[i].data.fd, &timers, 8);
                // Print stats about the server
                log_stats(db);
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
    tritedb.clients = hashtable_create(client_free);
    tritedb.peers = list_init();
    tritedb.expiring_keys = vector_init();
    tritedb.dbs = hashtable_create(database_free);
    tritedb.keyspace_size = 0LL;

    /* Create default database */
    Database *default_db = tmalloc(sizeof(Database));
    default_db->name = tstrdup("db0");
    default_db->data = trie_new();

    hashtable_put(tritedb.dbs, tstrdup(default_db->name), default_db);

    /* Initialize epollfd for server component */
    int epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        goto cleanup;
    }

    /* Initialize the sockets, first the server one */
    int fd = make_listen(addr, port, config.socket_family);

    /* Add eventfd to the loop, this time only in LT in order to wake up all
       threads */
    struct epoll_event ev;
    ev.data.fd = config.run;
    ev.events = EPOLLIN;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, config.run, &ev) < 0)
        perror("epoll_ctl(2): add epollin");

    /* Client structure for the server component */
    Client server = {
        .addr = addr,
        .fd = fd,
        .last_action_time = 0,
        .ctx_handler = accept_handler,
        .reply = NULL,
        .ptr = NULL,
        .db = NULL
    };

    /* Set socket in EPOLLIN flag mode, ready to read data */
    add_epoll(epollfd, fd, &server);

    tritedb.epollfd = epollfd;

    /* If it is run in CLUSTER mode add an additional descriptor and register
       it to the event loop */
    if (config.mode == CLUSTER) {

        /* Add 10k to the listening server port */
        int bport = atoi(port) + 10000;
        char bus_port[number_len(bport)];
        snprintf(tritedb.busport, sizeof(bus_port), "%d", bport);

        /* The bus one for distribution */
        int bfd = make_listen(addr, tritedb.busport, AF_INET);

        /* Client structure for the bus server component */
        Client bus_server = {
            .addr = addr,
            .fd = bfd,
            .last_action_time = 0,
            .ctx_handler = accept_handler,
            .reply = NULL,
            .ptr = NULL,
            .db = NULL
        };

        /* Set bus socket in EPOLLIN too */
        add_epoll(tritedb.epollfd, bfd, &bus_server);
    }

    tinfo("TriteDB v%s", config.version);
    if (config.socket_family == UNIX)
        tinfo("Starting server on %s", addr);
    else
        tinfo("Starting server on %s:%s", addr, port);

    if (config.mode == CLUSTER)
        tinfo("Opened bus port on %s:%s", addr, tritedb.busport);

    // Record start time
    info.start_time = time(NULL);

    run_server(&tritedb);

cleanup:

    /* Free all resources allocated */
    list_free(tritedb.peers, 1);
    hashtable_release(tritedb.clients);
    hashtable_release(tritedb.dbs);
    free_expiring_keys(tritedb.expiring_keys);

    tdebug("Bye\n");
    return 0;
}
