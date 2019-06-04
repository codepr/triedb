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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "db.h"
#include "util.h"
#include "protocol.h"
#include "pack.h"
#include "trie.h"


/* Unpack prototypes */

typedef size_t unpack_handler(const unsigned char *,
                              union header *,
                              union triedb_request *,
                              size_t);

static size_t unpack_triedb_put(const unsigned char *,
                                 union header *,
                                 union triedb_request *,
                                 size_t);

static size_t unpack_triedb_get(const unsigned char *,
                                 union header *,
                                 union triedb_request *,
                                 size_t);

static size_t unpack_triedb_ack(const unsigned char *,
                                union header *,
                                union triedb_request *,
                                size_t);

static size_t unpack_triedb_join(const unsigned char *,
                                 union header *,
                                 union triedb_request *,
                                 size_t);

// FIXME hack
static size_t unpack_triedb_join_res(const unsigned char *,
                                     union header *,
                                     union triedb_response *,
                                     size_t);
/*
 * Unpack functions mapping unpacking_handlers positioned in the array based
 * on message type
 */
static unpack_handler *unpack_handlers[16] = {
    NULL,
    unpack_triedb_put,
    unpack_triedb_get,
    unpack_triedb_get,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    unpack_triedb_ack,
    unpack_triedb_ack,
    unpack_triedb_join
};

/* Pack prototypes */

typedef unsigned char *pack_handler(const union triedb_response *);

static unsigned char *pack_response_ack(const union triedb_response *);

static unsigned char *pack_response_cnt(const union triedb_response *);

static unsigned char *pack_response_get(const union triedb_response *);

static unsigned char *pack_response_join(const union triedb_response *);

/*
 * Conversion table for response, maps OPCODE -> COMMAND_TYPE, it's still a
 * shitty abstraction, further improvements planned on future refactoring
 */

static pack_handler *pack_handlers[15] = {
    NULL,
    pack_response_ack,
    pack_response_get,
    pack_response_ack,
    pack_response_ack,
    pack_response_ack,
    pack_response_ack,
    pack_response_cnt,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    pack_response_join
};


static const int MAX_LEN_BYTES = 4;


/*
 * Encode Remaining Length on a packet header. It does not take into account
 * the bytes required to store itself. Refer to MQTT v3.1.1 algorithm for the
 * implementation.
 */
int encode_length(unsigned char *buf, size_t len) {

    int bytes = 0;

	do {

        if (bytes + 1 > MAX_LEN_BYTES)
            return bytes;

		char d = len % 128;
		len /= 128;

		/* if there are more digits to encode, set the top bit of this digit */
		if (len > 0)
			d |= 0x80;

		buf[bytes++] = d;

    } while (len > 0);

    return bytes;
}

/*
 * Decode Remaining Length comprised of Payload if present. It does not take
 * into account the bytes for storing length. Refer to MQTT v3.1.1 algorithm
 * for the implementation suggestion.
 *
 * TODO Handle case where multiplier > 128 * 128 * 128
 */
size_t decode_length(const unsigned char **buf, unsigned *pos) {

    char c;
	int multiplier = 1;
	unsigned long long value = 0LL;
    *pos = 0;

	do {
        c = **buf;
		value += (c & 127) * multiplier;
		multiplier *= 128;
        (*buf)++;
        (*pos)++;
    } while ((c & 128) != 0);

    return value;
}


static size_t unpack_triedb_put(const unsigned char *raw,
                                union header *hdr,
                                union triedb_request *pkt,
                                size_t len) {

    struct put put = { .header = *hdr };
    pkt->put = put;

    /* Read TTL and key len */
    unpack((unsigned char *) raw, "iH", &pkt->put.ttl, &pkt->put.keylen);

    size_t pkt_len = len;

    /*
     * Value len is calculated subtracting the length of the variable header
     * from the Remaining Length field that is in the Fixed Header
     */
    pkt_len -= (sizeof(int32_t) + sizeof(uint16_t) + pkt->put.keylen);

    char fmt[32];
    sprintf(fmt, "%ds%lds", pkt->put.keylen, pkt_len);

    pkt->put.key = tmalloc(pkt->put.keylen + 1);
    pkt->put.val = tmalloc(pkt_len + 1);

    /*
     * Move pointer forward of sizeof int + sizeof unsigned short, which
     * is the already read and unpacked bytes
     */
    unpack((unsigned char *) raw + 6, fmt, pkt->put.key, pkt->put.val);

    return len;
}


static size_t unpack_triedb_get(const unsigned char *raw,
                                union header *hdr,
                                union triedb_request *pkt,
                                size_t len) {

    struct get get = { .header = *hdr };
    pkt->get = get;

    /* Read key length and key of the soon-to-be-read value */
    pkt->get.key = tmalloc(len + 1);
    char fmt[10];
    sprintf(fmt, "%lds", len);
    unpack((unsigned char *) raw, fmt, pkt->get.key);

    return len;
}


static size_t unpack_triedb_ack(const unsigned char *raw,
                                union header *hdr,
                                union triedb_request *pkt,
                                size_t len) {

    struct ack info = { .header = *hdr };
    pkt->info = info;

    unpack((unsigned char *) raw, "BB", &(unsigned char){0}, &pkt->info.rc);

    return len;
}


static size_t unpack_triedb_join(const unsigned char *raw,
                                 union header *hdr,
                                 union triedb_request *pkt,
                                 size_t len) {

    struct ack join = { .header = *hdr };
    pkt->join_cluster = join;

    unpack((unsigned char *) raw, "BB",
           &(unsigned char){0}, &pkt->join_cluster.rc);

    return len;
}

// FIXME hack
static size_t unpack_triedb_join_res(const unsigned char *raw,
                                     union header *hdr,
                                     union triedb_response *pkt,
                                     size_t len) {

    struct join_response *response = tmalloc(sizeof(*response));
    response->header = *hdr;

    unpack((unsigned char *) raw, "H", &response->tuples_len);

    response->tuples = tmalloc(sizeof(struct tuple) * response->tuples_len);
    int keylen, vallen;
    char fmt[5];

    for (int i = 0; i < response->tuples_len; ++i) {
        unpack((unsigned char *) raw, "H", &keylen);
        sprintf(fmt, "%ds", keylen);
        unpack((unsigned char *) raw, fmt, &response->tuples[i].key);
        unpack((unsigned char *) raw, "H", &vallen);
        sprintf(fmt, "%ds", vallen);
        unpack((unsigned char *) raw, fmt, &response->tuples[i].val);
    }

    return len;
}


int unpack_triedb_request(const unsigned char *raw,
                          union triedb_request *pkt,
                          unsigned char opcode,
                          size_t len) {
    int rc = 0;

    union header header = { .byte = opcode };

    /* Call the appropriate unpack handler based on the message type */
    rc = unpack_handlers[header.bits.opcode](raw, &header, pkt, len);

    return rc;
}


int unpack_triedb_response(const unsigned char *raw,
                           union triedb_response *pkt,
                           unsigned char opcode,
                           size_t len) {
    int rc = 0;

    union header header = { .byte = opcode };

    /* Call the appropriate unpack handler based on the message type */
    // FIXME hack
    rc = unpack_triedb_join_res(raw, &header, pkt, len);

    return rc;
}


void triedb_request_destroy(union triedb_request *pkt) {

    switch (pkt->header.bits.opcode) {
        case PUT:
            tfree(pkt->put.key);
            break;
        case GET:
            tfree(pkt->get.key);
            break;
        case DEL:
            tfree(pkt->get.key);
            break;
    }

    tfree(pkt);
}


struct ack_response *ack_response(unsigned char byte, unsigned char rc) {
    struct ack_response *response = tmalloc(sizeof(*response));
    response->header.byte = byte;
    response->rc = rc;
    return response;
}


struct cnt_response *cnt_response(unsigned char byte, unsigned long long val) {
    struct cnt_response *response = tmalloc(sizeof(*response));
    response->header.byte = byte;
    response->val = val;
    return response;
}


struct get_response *get_response(unsigned char byte, const void *arg) {

    struct get_response *response = tmalloc(sizeof(*response));
    response->header.byte = byte;

    /*
     * Get response can be either single or prefix, the latter returns a list
     * of items instead of a single one, where each item corresponds to an
     * existing key in the database
     */
    if (response->header.bits.prefix == 1) {
        Vector *tuples = (Vector *) arg;
        response->tuples_len = tuples->size;
        response->tuples = tmalloc(tuples->size * sizeof(struct tuple));

        /*
         * Create the tuples array containing required informations from the
         * vector returned from the range query on the Trie
         */
        for (int i = 0; i < vector_size(tuples); ++i) {
            struct kv_obj *kv = vector_get(tuples, i);
            const struct db_item *item = kv->data;
            response->tuples[i].key = (unsigned char *) kv->key;
            response->tuples[i].val = item->data;
            response->tuples[i].keylen = strlen(kv->key);
            response->tuples[i].ttl = item->ttl;
        }
    } else {
        // Single response here
        struct tuple *tuple = (struct tuple *) arg;

        // Copy content of the tuple
        response->val = *tuple;
    }

    return response;
}


struct join_response *join_response(unsigned char byte, const Vector *v) {

    struct join_response *response = tmalloc(sizeof(*response));
    response->header.byte = byte;

    /*
     * Join response returns a list of items instead of a single one, where
     * each item corresponds to an existing key in the database
     */
    response->tuples_len = v->size;
    response->tuples = tmalloc(v->size * sizeof(struct tuple));

    /*
     * Create the tuples array containing required informations from the
     * vector returned from the range query on the Trie
     */
    for (int i = 0; i < vector_size(v); ++i) {
        struct kv_obj *kv = vector_get(v, i);
        const struct db_item *item = kv->data;
        response->tuples[i].key = (unsigned char *) kv->key;
        response->tuples[i].val = item->data;
        response->tuples[i].keylen = strlen(kv->key);
        response->tuples[i].ttl = item->ttl;
    }

    return response;
}


void get_response_destroy(struct get_response *response) {
    if (response->header.bits.prefix == 1)
        tfree(response->tuples);
    tfree(response);
}


void join_response_destroy(struct join_response *response) {
    tfree(response->tuples);
    tfree(response);
}


static unsigned char *pack_response_ack(const union triedb_response *res) {
    unsigned char *raw = tmalloc(3);
    pack(raw, "BBB", res->ack_res.header.byte, 1, res->ack_res.rc);
    return raw;
}


static unsigned char *pack_response_cnt(const union triedb_response *res) {
    unsigned char *raw = tmalloc(10);
    pack(raw, "BBQ", res->cnt_res.header.byte, 8, res->cnt_res.val);
    return raw;
}


static unsigned char *pack_response_get(const union triedb_response *res) {

    unsigned char *raw = NULL;

    size_t length = 0;

    if (res->get_res.header.bits.prefix == 1) {

        /* Init length with the size of the tuples_len field (u16) */
        length = sizeof(unsigned short);

        /* Pre-compute the total length of the entire packet and encode it */
        for (int i = 0; i < res->get_res.tuples_len; ++i)
            length += res->get_res.tuples[i].keylen
                + strlen((const char *) res->get_res.tuples[i].val)
                + sizeof(int)
                + sizeof(unsigned short) * 2;

        raw = tmalloc(length + 2);

        /* Encode the byte, the length and the tuples len */
        pack(raw, "B", res->get_res.header.byte);
        int steps = encode_length(raw + 1, length);
        pack(raw + steps + 1, "H", res->get_res.tuples_len);

        /*
         * Move forward pointer of 3 + steps -> byte + unsigned short + steps
         * (bytes required to store packet length, max 4), the portion of the
         * packet already written and packed
         */
        unsigned char *p = raw + 3 + steps;

        /* Start encoding the tuples */
        int pos = 0;
        for (int i = 0; i < res->get_res.tuples_len; ++i) {
            pack(p + pos, "iHsHs", res->get_res.tuples[i].ttl,
                 res->get_res.tuples[i].keylen,
                 res->get_res.tuples[i].key,
                 strlen((const char *) res->get_res.tuples[i].val),
                 res->get_res.tuples[i].val);
            /* Update position index */
            pos += res->get_res.tuples[i].keylen
                + strlen((const char *) res->get_res.tuples[i].val)
                + sizeof(int)
                + sizeof(unsigned short) * 2;
        }

    } else {

        length = res->get_res.val.keylen
            + strlen((const char *) res->get_res.val.val)
            + sizeof(int)
            + sizeof(unsigned short);

        raw = tmalloc(length + 2);

        pack(raw, "B", res->get_res.header.byte);
        int steps = encode_length(raw + 1, length);
        pack(raw + steps + 1, "iHss", res->get_res.val.ttl,
             res->get_res.val.keylen,
             res->get_res.val.key,
             res->get_res.val.val);
    }

    return raw;
}


static unsigned char *pack_response_join(const union triedb_response *res) {

    unsigned char *raw = NULL;

    /* Init length with the size of the tuples_len field (u16) */
    size_t length = sizeof(unsigned short);

    /* Pre-compute the total length of the entire packet and encode it */
    for (int i = 0; i < res->join_res.tuples_len; ++i)
        length += res->join_res.tuples[i].keylen
            + strlen((const char *) res->join_res.tuples[i].val)
            + sizeof(int)
            + sizeof(unsigned short) * 2;

    raw = tmalloc(length + 2);

    /* Encode the byte, the length and the tuples len */
    pack(raw, "B", res->join_res.header.byte);
    int steps = encode_length(raw + 1, length);
    pack(raw + steps + 1, "H", res->join_res.tuples_len);

    /*
     * Move forward pointer of 3 + steps -> byte + unsigned short + steps
     * (bytes required to store packet length, max 4), the portion of the
     * packet already written and packed
     */
    unsigned char *p = raw + 3 + steps;

    /* Start encoding the tuples */
    int pos = 0;
    for (int i = 0; i < res->join_res.tuples_len; ++i) {
        pack(p + pos, "iHsHs", res->join_res.tuples[i].ttl,
             res->join_res.tuples[i].keylen,
             res->join_res.tuples[i].key,
             strlen((const char *) res->join_res.tuples[i].val),
             res->join_res.tuples[i].val);
        /* Update position index */
        pos += res->join_res.tuples[i].keylen
            + strlen((const char *) res->join_res.tuples[i].val)
            + sizeof(int)
            + sizeof(unsigned short) * 2;
    }

    return raw;
}


bstring pack_ack(unsigned char byte, unsigned char rc) {
    unsigned char raw[3];
    pack(raw, "BBB", byte, 1, rc);
    return bstring_copy((const char *) raw, 3);
}


bstring pack_cnt(unsigned char byte, unsigned long long val) {
    unsigned char raw[10];
    pack(raw, "BBQ", byte, 8, val);
    return bstring_copy((const char *) raw, 10);
}

/* Helper function to create a bytearray with all informations stored in */
bstring pack_info(const struct config *conf,
                  const struct informations *infos) {
    size_t vlen = strlen(conf->version);
    size_t llen = strlen(conf->logpath);
    size_t hlen = strlen(conf->hostname);
    size_t plen = strlen(conf->port);

    /*
     * Add + 1 to each string length to store the length in a byte just before
     * the bytestring
     */
    size_t size = vlen + 1
        + llen + 1
        + hlen + 1
        + plen + 1
        + sizeof(unsigned char)   // override of conf->mode type
        + sizeof(conf->loglevel)
        + sizeof(unsigned char)   // override of conf->socket_family
        + sizeof(conf->max_memory)
        + sizeof(conf->max_request_size)
        + sizeof(conf->mem_reclaim_time)
        + sizeof(conf->tcp_backlog)
        + sizeof(infos->nclients)
        + sizeof(infos->nconnections)
        + sizeof(infos->start_time)
        + sizeof(infos->uptime)
        + sizeof(infos->nrequests)
        + sizeof(infos->bytes_recv)
        + sizeof(infos->bytes_sent)
        + sizeof(infos->nkeys);

    /* Add +1 to store the code INFO on the header */
    bstring raw = bstring_empty(size + 1);

    /* 0xd0 == dec(208) == 11010000 == INFO opcode */
    pack(raw, "BIIQQIQQQBBBQQQiBsBsBsBs",
         0xd0,
         infos->nclients,
         infos->nconnections,
         infos->start_time,
         infos->uptime,
         infos->nrequests,
         infos->bytes_recv,
         infos->bytes_sent,
         infos->nkeys,
         conf->mode,
         conf->loglevel,
         conf->socket_family,
         conf->max_memory,
         conf->mem_reclaim_time,
         conf->max_request_size,
         conf->tcp_backlog,
         vlen,
         conf->version,
         llen,
         conf->logpath,
         hlen,
         conf->hostname,
         plen,
         conf->port);

    return raw;
}


unsigned char *pack_response(const union triedb_response *res, unsigned type) {
    return pack_handlers[type](res);
}
