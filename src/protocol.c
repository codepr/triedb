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


/*
 * Unpack functions mapping unpacking_handlers positioned in the array based
 * on message type
 */
static unpack_handler *unpack_handlers[4] = {
    NULL,
    unpack_triedb_put,
    unpack_triedb_get,
    unpack_triedb_get
};

/* Pack prototypes */

typedef void pack_handler(unsigned char *, const union triedb_response *);

static void pack_response_ack(unsigned char *, const union triedb_response *);

static void pack_response_cnt(unsigned char *, const union triedb_response *);

/*
 * Conversion table for response, maps OPCODE -> COMMAND_TYPE, it's still a
 * shitty abstraction, further improvements planned on future refactoring
 */

static pack_handler *pack_handlers[8] = {
    NULL,
    pack_response_ack,
    NULL,
    pack_response_ack,
    pack_response_ack,
    pack_response_ack,
    pack_response_ack,
    pack_response_cnt
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

    // TTL check
    pkt->put.ttl = unpack_i32((const uint8_t **) &raw);

    /* Read topic length and topic of the soon-to-be-published message */
    uint16_t keylen = unpack_u16((const uint8_t **) &raw);
    pkt->put.keylen = keylen;
    pkt->put.key = tmalloc(keylen + 1);
    unpack_bytes((const uint8_t **) &raw, keylen, pkt->put.key);

    size_t pkt_len = len;

    /*
     * Message len is calculated subtracting the length of the variable header
     * from the Remaining Length field that is in the Fixed Header
     */
    pkt_len -= (sizeof(int32_t) + sizeof(uint16_t) + keylen);
    pkt->put.val = tmalloc(pkt_len + 1);
    unpack_bytes((const uint8_t **) &raw, pkt_len, pkt->put.val);

    return len;
}


static size_t unpack_triedb_get(const unsigned char *raw,
                                 union header *hdr,
                                 union triedb_request *pkt,
                                 size_t len) {

    struct get get = { .header = *hdr };
    pkt->get = get;

    /* Read topic length and topic of the soon-to-be-published message */
    pkt->get.key = tmalloc(len + 1);
    unpack_bytes((const uint8_t **) &raw, len, pkt->get.key);

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


void triedb_request_destroy(union triedb_request *pkt) {

    switch (pkt->header.bits.opcode) {
        case PUT:
            tfree(pkt->put.key);
            tfree(pkt->put.val);
            break;
        case GET:
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


struct get_response *get_response(unsigned char byte, Vector *tuples) {

    struct get_response *response = tmalloc(sizeof(*response));
    response->header.byte = byte;
    response->tuples_len = tuples->size;
    response->tuples = tmalloc(tuples->size * sizeof(struct tuple));

    /*
     * Create the tuples array containing required informations from the
     * vector returned from the range query on the Trie
     */
    for (int i = 0; i < vector_size(tuples); i++) {
        struct kv_obj *kv = vector_get(tuples, i);
        const struct db_item *item = kv->data;
        response->tuples[i].key = (unsigned char *) kv->key;
        response->tuples[i].val = item->data;
        response->tuples[i].keylen = strlen(kv->key);
        response->tuples[i].ttl = item->ttl;
    }

    return response;
}


static void pack_response_ack(unsigned char *raw,
                              const union triedb_response *res) {
    pack_u8(&raw, res->ack_res.header.byte);
    encode_length(raw, 1);
    pack_u8(&raw, res->ack_res.rc);
}


static void pack_response_cnt(unsigned char *raw,
                              const union triedb_response *res) {
    pack_u8(&raw, res->cnt_res.header.byte);
    encode_length(raw, 1);
    pack_u64(&raw, res->cnt_res.val);
}


bstring pack_ack(unsigned char byte, unsigned rc) {
    unsigned char raw[3];
    unsigned char *praw = &raw[0];
    pack_u8(&praw, byte);
    encode_length(praw, 1);
    pack_u8(&praw, rc);
    return bstring_copy((const char *) raw, 3);
}


bstring pack_cnt(unsigned char byte, unsigned long long val) {
    unsigned char raw[10];
    unsigned char *praw = &raw[0];
    pack_u8(&praw, byte);
    encode_length(praw, 1);
    pack_u64(&praw, val);
    return bstring_copy((const char *) raw, 10);
}


void pack_response(unsigned char *raw,
                   const union triedb_response *res, unsigned type) {
    pack_handlers[type](raw, res);
}
