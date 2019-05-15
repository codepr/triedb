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
#include "util.h"
#include "protocol.h"
#include "pack.h"


typedef size_t unpack_handler(const unsigned char *,
                              union header *,
                              union triedb_packet *,
                              size_t);

static size_t unpack_triedb_put(const unsigned char *,
                                 union header *,
                                 union triedb_packet *,
                                 size_t);

static size_t unpack_triedb_get(const unsigned char *,
                                 union header *,
                                 union triedb_packet *,
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
                                 union triedb_packet *pkt,
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
                                 union triedb_packet *pkt,
                                 size_t len) {

    struct get get = { .header = *hdr };
    pkt->get = get;

    /* Read topic length and topic of the soon-to-be-published message */
    pkt->get.key = tmalloc(len + 1);
    unpack_bytes((const uint8_t **) &raw, len, pkt->get.key);

    return len;
}


int unpack_triedb_packet(const unsigned char *raw,
                          union triedb_packet *pkt,
                          unsigned char opcode,
                          size_t len) {

    int rc = 0;

    union header header = { .byte = opcode };

    /* Call the appropriate unpack handler based on the message type */
    rc = unpack_handlers[header.bits.opcode](raw, &header, pkt, len);

    return rc;
}


void triedb_packet_destroy(union triedb_packet *pkt) {

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
/* #<{(| */
/*  * Conversion table for request, maps OPCODE -> COMMAND_TYPE, it's still a */
/*  * shitty abstraction, further improvements planned on future refactoring */
/*  |)}># */
/* static const uint8_t opcode_req_map[COMMAND_COUNT][2] = { */
/*     {ACK, EMPTY_COMMAND}, */
/*     {PUT, KEY_VAL_COMMAND}, */
/*     {GET, KEY_COMMAND}, */
/*     {DEL, KEY_LIST_COMMAND}, */
/*     {TTL, KEY_COMMAND}, */
/*     {INC, KEY_LIST_COMMAND}, */
/*     {DEC, KEY_LIST_COMMAND}, */
/*     {COUNT, KEY_COMMAND}, */
/*     {KEYS, KEY_COMMAND}, */
/*     {USE, KEY_COMMAND}, */
/*     {CLUSTER_JOIN, KEY_VAL_COMMAND}, */
/*     {CLUSTER_MEMBERS, KEY_VAL_LIST_COMMAND}, */
/*     {PING, EMPTY_COMMAND}, */
/*     {DB, EMPTY_COMMAND}, */
/*     {INFO, EMPTY_COMMAND}, */
/*     {QUIT, EMPTY_COMMAND} */
/* }; */
/*  */
/* #<{(| */
/*  * Conversion table for response, maps OPCODE -> CONTENT_TYPE, it's still a */
/*  * shitty abstraction, further improvements planned on future refactoring */
/*  |)}># */
/* static const uint8_t opcode_res_map[9][2] = { */
/*     {ACK, NO_CONTENT}, */
/*     {GET, DATA_CONTENT}, */
/*     {DEL, NO_CONTENT}, */
/*     {TTL, NO_CONTENT}, */
/*     {INC, NO_CONTENT}, */
/*     {DEC, NO_CONTENT}, */
/*     {COUNT, VALUE_CONTENT}, */
/*     {KEYS, LIST_CONTENT}, */
/*     {CLUSTER_MEMBERS, KVLIST_CONTENT} */
/* }; */
/*  */
/*  */
/* static void pack_header(const struct header *, struct buffer *); */
/* static void unpack_header(struct buffer *, struct header *); */
/* static void free_header(struct header *); */
/* static struct command *unpack_command(struct buffer *, struct header *); */
/* static void free_command_header(struct command *); */
/* static void free_command(struct command *, bool); */
/* static void header_init(struct header *, uint8_t, uint32_t, uint8_t, const char *); */
/* static int8_t get_command_type(uint8_t); */
/* static int8_t get_content_type(uint8_t); */
/*  */
/*  */
/* static int8_t get_command_type(uint8_t opcode) { */
/*  */
/*     int ctype = -1; */
/*  */
/*     for (int i = 0; i < COMMAND_COUNT && ctype == -1; i++) */
/*         if (opcode_req_map[i][0] == opcode) */
/*             ctype = opcode_req_map[i][1]; */
/*  */
/*     return ctype; */
/* } */
/*  */
/*  */
/* static int8_t get_content_type(uint8_t opcode) { */
/*  */
/*     int cctype = -1; */
/*  */
/*     for (int i = 0; i < 9 && cctype == -1; i++) */
/*         if (opcode_res_map[i][0] == opcode) */
/*             cctype = opcode_res_map[i][1]; */
/*  */
/*     return cctype; */
/* } */
/*  */
/*  */
/* static void pack_header(const struct header *h, struct buffer *b) { */
/*  */
/*     assert(b && h); */
/*  */
/*     pack(b, "BIB", h->opcode, b->size, h->flags); */
/*  */
/*     if ((h->flags & F_FROMNODEREQUEST) || (h->flags & F_FROMNODERESPONSE)) */
/*         pack(b, "s", h->transaction_id); */
/*  */
/* } */
/*  */
/*  */
/* static void unpack_header(struct buffer *b, struct header *h) { */
/*  */
/*     assert(b && h); */
/*  */
/*     unpack(b, "BIB", &h->opcode, &h->size, &h->flags); */
/*  */
/*     if (h->flags & F_FROMNODEREQUEST || h->flags & F_FROMNODERESPONSE) { */
/*         const char transaction_id[UUID_LEN]; */
/*         char fmt[4]; */
/*         snprintf(fmt, 4, "%ds", UUID_LEN - 1); */
/*         unpack(b, fmt, transaction_id); */
/*         strcpy(h->transaction_id, transaction_id); */
/*     } */
/* } */
/*  */
/*  */
/* static void free_header(struct header *header) { */
/*     tfree(header); */
/* } */
/*  */
/*  */
/* static void free_command_header(struct command *command) { */
/*  */
/*     if (!command) */
/*         return; */
/*  */
/*     switch (command->cmdtype) { */
/*         case EMPTY_COMMAND: */
/*             free_header(command->ecommand->header); */
/*             break; */
/*         case KEY_COMMAND: */
/*             free_header(command->kcommand->header); */
/*             break; */
/*         case KEY_VAL_COMMAND: */
/*             free_header(command->kvcommand->header); */
/*             break; */
/*         case KEY_LIST_COMMAND: */
/*             free_header(command->klcommand->header); */
/*             break; */
/*     } */
/* } */
/*  */
/*  */
/* static void free_command(struct command *command, bool with_header) { */
/*  */
/*     if (!command) */
/*         return; */
/*  */
/*     switch (command->cmdtype) { */
/*         case EMPTY_COMMAND: */
/*             if (with_header) */
/*                 free_header(command->ecommand->header); */
/*             tfree(command->ecommand); */
/*             break; */
/*         case KEY_COMMAND: */
/*             if (with_header) */
/*                 free_header(command->kcommand->header); */
/*             tfree(command->kcommand->key); */
/*             tfree(command->kcommand); */
/*             break; */
/*         case KEY_VAL_COMMAND: */
/*             if (with_header) */
/*                 free_header(command->kvcommand->header); */
/*             tfree(command->kvcommand->key); */
/*             tfree(command->kvcommand->val); */
/*             tfree(command->kvcommand); */
/*             break; */
/*         case KEY_LIST_COMMAND: */
/*             if (with_header) */
/*                 free_header(command->klcommand->header); */
/*             for (int i = 0; i < command->klcommand->len; i++) { */
/*                 tfree(command->klcommand->keys[i]->key); */
/*                 tfree(command->klcommand->keys[i]); */
/*             } */
/*             tfree(command->klcommand->keys); */
/*             tfree(command->klcommand); */
/*             break; */
/*     } */
/*  */
/*     tfree(command); */
/* } */
/*  */
/*  */
/* static void header_init(struct header *header, uint8_t opcode, uint32_t size, */
/*                         uint8_t flags, const char *transaction_id) { */
/*  */
/*     header->opcode = opcode; */
/*     header->size = size; */
/*     header->flags = 0 | flags; */
/*  */
/*     if (transaction_id && (flags & F_FROMNODERESPONSE)) { */
/*         strncpy(header->transaction_id, */
/*                 (const char *) transaction_id, UUID_LEN - 1); */
/*         header->transaction_id[UUID_LEN - 1] = '\0'; */
/*         header->size += UUID_LEN - 1; */
/*     } */
/* } */
/*  */
/*  */
/* #<{(|******************************************* */
/*  *         REQUEST PACKING FUNCTIONS */
/*  *******************************************|)}># */
/*  */
/*  */
/* void pack_request(struct buffer *buffer, */
/*                   const struct request *request, int reqtype) { */
/*  */
/*     assert(buffer && request); */
/*  */
/*     // FIXME make it consistent with the rest */
/*     switch (reqtype) { */
/*         case KEY_COMMAND: */
/*             pack_header(request->command->kcommand->header, buffer); */
/*             pack_u16(buffer, request->command->kcommand->keysize); */
/*             pack_bytes(buffer, request->command->kcommand->key); */
/*             pack_u8(buffer, request->command->kcommand->is_prefix); */
/*             pack_u16(buffer, request->command->kcommand->ttl); */
/*             break; */
/*         case KEY_VAL_COMMAND: */
/*             pack_header(request->command->kvcommand->header, buffer); */
/*             pack_u16(buffer, request->command->kvcommand->keysize); */
/*             pack_u32(buffer, request->command->kvcommand->valsize); */
/*             pack_bytes(buffer, request->command->kvcommand->key); */
/*             pack_bytes(buffer, request->command->kvcommand->val); */
/*             pack_u8(buffer, request->command->kvcommand->is_prefix); */
/*             pack_u16(buffer, request->command->kvcommand->ttl); */
/*             break; */
/*         case KEY_LIST_COMMAND: */
/*             pack_header(request->command->klcommand->header, buffer); */
/*             pack_u32(buffer, request->command->klcommand->len); */
/*             for (int i = 0; i < request->command->klcommand->len; i++) { */
/*                 pack_u16(buffer, */
/*                          request->command->klcommand->keys[i]->keysize); */
/*                 pack_bytes(buffer, */
/*                            request->command->klcommand->keys[i]->key); */
/*                 pack_u8(buffer, */
/*                         request->command->klcommand->keys[i]->is_prefix); */
/*             } */
/*             break; */
/*         default: */
/*             fprintf(stderr, "Pack request: not implemented yet\n"); */
/*             break; */
/*     } */
/* } */
/*  */
/*  */
/* struct request *unpack_request(struct buffer *b) { */
/*  */
/*     assert(b); */
/*  */
/*     struct request *request = tmalloc(sizeof(*request)); */
/*     if (!request) */
/*         return NULL; */
/*  */
/*     struct header *header = tmalloc(sizeof(*header)); */
/*     if (!header) */
/*         goto errnomem2; */
/*  */
/*     unpack_header(b, header); */
/*  */
/*     if (!(header->flags & F_BULKREQUEST)) { */
/*         #<{(| It's a single request, just unpack it into the request pointer |)}># */
/*         request->reqtype = SINGLE_REQUEST; */
/*         request->command = unpack_command(b, header); */
/*     } else { */
/*         #<{(| */
/*          * Unpack the bulk request format, a request formed by a list of */
/*          * single requests. */
/*          |)}># */
/*         request->reqtype = BULK_REQUEST; */
/*         request->bulk_command = tmalloc(sizeof(struct bulk_command)); */
/*         if (!request->bulk_command) */
/*             goto errnomem1; */
/*  */
/*         uint32_t ncommands = unpack_u32(b); */
/*         request->bulk_command->ncommands = ncommands; */
/*         request->bulk_command->commands = */
/*             tmalloc(ncommands * sizeof(struct command)); */
/*  */
/*         #<{(| Unpack each single packet into the array of requests |)}># */
/*         for (uint32_t i = 0; i < ncommands; i++) */
/*             request->bulk_command->commands[i] = unpack_command(b, header); */
/*     } */
/*  */
/*     return request; */
/*  */
/* errnomem1: */
/*  */
/*     tfree(header); */
/*  */
/* errnomem2: */
/*  */
/*     tfree(request); */
/*     return NULL; */
/* } */
/*  */
/* #<{(| */
/*  * Main unpacking function, to translates bytes received from clients in */
/*  * network byte-order (big-endian) to a command structure, based on the opcode */
/*  |)}># */
/* static struct command *unpack_command(struct buffer *b, */
/*                                       struct header *header) { */
/*  */
/*     assert(b && header); */
/*  */
/*     struct command *command = tmalloc(sizeof(*command)); */
/*     if (!command) */
/*         return NULL; */
/*  */
/*     command->cmdtype = get_command_type(header->opcode); */
/*  */
/*     switch (command->cmdtype) { */
/*         case EMPTY_COMMAND: */
/*             command->ecommand = tmalloc(sizeof(struct empty_command)); */
/*             if (!command->ecommand) */
/*                 goto errnomem3; */
/*  */
/*             command->ecommand->header = header; */
/*             break; */
/*         case KEY_COMMAND: */
/*             command->kcommand = tmalloc(sizeof(struct key_command)); */
/*             if (!command->kcommand) */
/*                 goto errnomem3; */
/*  */
/*             command->kcommand->header = header; */
/*  */
/*             // Mandatory fields */
/*             command->kcommand->keysize = unpack_u16(b); */
/*             command->kcommand->key = unpack_bytes(b, */
/*                                                   command->kcommand->keysize); */
/*  */
/*             // Optional fields */
/*             command->kcommand->is_prefix = unpack_u8(b); */
/*             command->kcommand->ttl = unpack_u16(b); */
/*  */
/*             break; */
/*  */
/*         case KEY_VAL_COMMAND: */
/*             command->kvcommand = tmalloc(sizeof(struct keyval_command)); */
/*             if (!command->kvcommand) */
/*                 goto errnomem3; */
/*  */
/*             command->kvcommand->header = header; */
/*  */
/*             // Mandatory fields */
/*             command->kvcommand->keysize = unpack_u16(b); */
/*             command->kvcommand->valsize = unpack_u32(b); */
/*             command->kvcommand->key = */
/*                 unpack_bytes(b, command->kvcommand->keysize); */
/*             command->kvcommand->val = */
/*                 unpack_bytes(b, command->kvcommand->valsize); */
/*  */
/*             // Optional fields */
/*             command->kvcommand->is_prefix = unpack_u8(b); */
/*             command->kvcommand->ttl = unpack_u16(b); */
/*  */
/*             break; */
/*  */
/*         case KEY_LIST_COMMAND: */
/*             command->klcommand = tmalloc(sizeof(struct key_list_command)); */
/*             if (!command->klcommand) */
/*                 goto errnomem3; */
/*  */
/*             command->klcommand->header = header; */
/*  */
/*             // Number of keys, or length of the Key array */
/*             command->klcommand->len = unpack_u32(b); */
/*  */
/*             command->klcommand->keys = tcalloc(command->klcommand->len, */
/*                                                sizeof(struct key)); */
/*  */
/*             if (!command->klcommand->keys) */
/*                 goto errnomem2; */
/*  */
/*             for (int i = 0; i < command->klcommand->len; i++) { */
/*  */
/*                 struct key *key = tmalloc(sizeof(*key)); */
/*                 if (!key) */
/*                     goto errnomem1; */
/*  */
/*                 key->keysize = unpack_u16(b); */
/*                 key->key = unpack_bytes(b, key->keysize); */
/*                 key->is_prefix = unpack_u8(b); */
/*                 command->klcommand->keys[i] = key; */
/*             } */
/*  */
/*             break; */
/*  */
/*         default: */
/*             tfree(header); */
/*             tfree(command); */
/*             command = NULL; */
/*             break; */
/*     }; */
/*  */
/*     return command; */
/*  */
/* errnomem1: */
/*  */
/*     tfree(command->klcommand->keys); */
/*  */
/* errnomem2: */
/*  */
/*     tfree(command->klcommand); */
/*  */
/* errnomem3: */
/*  */
/*     tfree(command); */
/*     return NULL; */
/* } */
/*  */
/*  */
/* void free_request(struct request *request) { */
/*  */
/*     if (!request) */
/*         return; */
/*  */
/*     if (request->reqtype == SINGLE_REQUEST) { */
/*         free_command(request->command, true); */
/*     } else { */
/*  */
/*         // FIXME hack, free the first pointer */
/*         free_command_header(request->bulk_command->commands[0]); */
/*         for (int i = 0; i < request->bulk_command->ncommands; i++) */
/*             free_command(request->bulk_command->commands[i], false); */
/*  */
/*         tfree(request->bulk_command->commands); */
/*         tfree(request->bulk_command); */
/*     } */
/*  */
/*     tfree(request); */
/* } */
/*  */
/* #<{(|******************************************* */
/*  *             REQUEST HELPERS */
/*  *******************************************|)}># */
/*  */
/* #define make_cluster_join_request(addr) make_key_request(addr, CLUSTER_JOIN, \ */
/*                                                          0x00, 0x00,         \ */
/*                                                          F_FROMNODEREQUEST); \ */
/*  */
/*  */
/* struct request *make_key_request(const uint8_t *key, uint8_t opcode, */
/*                                  uint16_t ttl, uint8_t flags) { */
/*  */
/*     struct request *request = tmalloc(sizeof(*request)); */
/*     if (!request) */
/*         goto err; */
/*  */
/*     request->reqtype = SINGLE_REQUEST; */
/*     request->command = tmalloc(sizeof(struct command)); */
/*     if (!request->command) */
/*         goto errnomem1; */
/*  */
/*     request->command->cmdtype = KEY_COMMAND; */
/*     request->command->kcommand = tmalloc(sizeof(struct key_command)); */
/*     if (!request->command->kcommand) */
/*         goto errnomem2; */
/*  */
/*     request->command->kcommand->header = tmalloc(sizeof(struct header)); */
/*     if (!request->command->kcommand->header) */
/*         goto errnomem3; */
/*  */
/*     request->command->kcommand->header->size = HEADERLEN + */
/*         (2 * sizeof(uint16_t)) + strlen((const char *) key) + sizeof(uint8_t); */
/*  */
/*     request->command->kcommand->header->flags = 0 | flags; */
/*  */
/*     if (flags & F_FROMNODEREQUEST) { */
/*         char uuid[UUID_LEN]; */
/*         generate_uuid(uuid); */
/*         strcpy(request->command->kcommand->header->transaction_id, uuid); */
/*         request->command->kcommand->header->size += UUID_LEN - 1; */
/*     } */
/*  */
/*     request->command->kcommand->header->opcode = opcode; */
/*  */
/*     request->command->kcommand->keysize = strlen((const char *) key); */
/*     request->command->kcommand->key = (uint8_t *) tstrdup((const char *) key); */
/*  */
/*     request->command->kcommand->ttl = ttl; */
/*     request->command->kcommand->is_prefix = flags & F_PREFIXREQUEST ? 1 : 0; */
/*  */
/*     return request; */
/*  */
/* errnomem3: */
/*  */
/*     tfree(request->command->kcommand); */
/*  */
/* errnomem2: */
/*  */
/*     tfree(request->command); */
/*  */
/* errnomem1: */
/*  */
/*     tfree(request); */
/*  */
/* err: */
/*  */
/*     return NULL; */
/* } */
/*  */
/*  */
/* struct request *make_keyval_request(const uint8_t *key, */
/*                                     const uint8_t *val, */
/*                                     uint8_t opcode, */
/*                                     uint16_t ttl, */
/*                                     uint8_t flags) { */
/*  */
/*     struct request *request = tmalloc(sizeof(*request)); */
/*     if (!request) */
/*         goto err; */
/*  */
/*     request->reqtype = SINGLE_REQUEST; */
/*     request->command = tmalloc(sizeof(struct command)); */
/*     if (!request->command) */
/*         goto errnomem1; */
/*  */
/*     request->command->cmdtype = KEY_VAL_COMMAND; */
/*     request->command->kvcommand = tmalloc(sizeof(struct keyval_command)); */
/*     if (!request->command->kvcommand) */
/*         goto errnomem2; */
/*  */
/*     request->command->kvcommand->header = tmalloc(sizeof(struct header)); */
/*     if (!request->command->kvcommand->header) */
/*         goto errnomem3; */
/*  */
/*     request->command->kvcommand->header->size = HEADERLEN + */
/*         (2 * sizeof(uint16_t)) + strlen((const char *) key) + */
/*         sizeof(uint32_t) + strlen((const char *) val) + sizeof(uint8_t); */
/*  */
/*     request->command->kvcommand->header->flags = 0 | flags; */
/*  */
/*     if (flags & F_FROMNODEREQUEST) { */
/*         char uuid[UUID_LEN]; */
/*         generate_uuid(uuid); */
/*         strcpy(request->command->kvcommand->header->transaction_id, uuid); */
/*         request->command->kvcommand->header->size += UUID_LEN - 1; */
/*     } */
/*  */
/*     request->command->kvcommand->header->opcode = opcode; */
/*  */
/*     request->command->kvcommand->keysize = strlen((const char *) key); */
/*     request->command->kvcommand->key = (uint8_t *) tstrdup((const char *) key); */
/*  */
/*     request->command->kvcommand->valsize = strlen((const char *) val); */
/*     request->command->kvcommand->val = (uint8_t *) tstrdup((const char *) val); */
/*  */
/*     request->command->kvcommand->ttl = ttl; */
/*     request->command->kvcommand->is_prefix = flags & F_PREFIXREQUEST ? 1 : 0; */
/*  */
/*     return request; */
/*  */
/* errnomem3: */
/*  */
/*     tfree(request->command->kvcommand); */
/*  */
/* errnomem2: */
/*  */
/*     tfree(request->command); */
/*  */
/* errnomem1: */
/*  */
/*     tfree(request); */
/*  */
/* err: */
/*  */
/*     return NULL; */
/*  */
/* } */
/*  */
/*  */
/* struct request *make_keylist_request(const List *content, */
/*                                      uint8_t opcode, */
/*                                      const uint8_t *transaction_id, */
/*                                      uint8_t flags) { */
/*  */
/*     struct request *request = tmalloc(sizeof(*request)); */
/*     if (!request) */
/*         return NULL; */
/*  */
/*     request->reqtype = SINGLE_REQUEST; */
/*     request->command = tmalloc(sizeof(struct command)); */
/*     if (!request->command) { */
/*         tfree(request->command); */
/*         return NULL; */
/*     } */
/*  */
/*     request->command->klcommand = tmalloc(sizeof(struct key_list_command)); */
/*     if (!request->command->klcommand) { */
/*         tfree(request->command); */
/*         tfree(request); */
/*         return NULL; */
/*     } */
/*  */
/*     request->command->klcommand->header = tmalloc(sizeof(struct header)); */
/*     if (!request->command->klcommand->header) { */
/*         tfree(request->command->klcommand); */
/*         tfree(request->command); */
/*         tfree(request); */
/*         return NULL; */
/*     } */
/*  */
/*     request->command->cmdtype = KEY_LIST_COMMAND; */
/*  */
/*     header_init(request->command->klcommand->header, */
/*                 opcode, HEADERLEN + sizeof(uint32_t), */
/*                 flags, (const char *) transaction_id); */
/*  */
/*     request->command->klcommand->len = content->len; */
/*     request->command->klcommand->keys = */
/*         tmalloc(content->len * sizeof(struct key)); */
/*  */
/*     int i = 0; */
/*  */
/*     for (struct list_node *cur = content->head; cur; cur = cur->next) { */
/*         struct key *key = tmalloc(sizeof(*key)); */
/*         key->key = (uint8_t *) tstrdup((const char *) cur->data); */
/*         key->keysize = strlen((const char *) cur->data); */
/*         request->command->klcommand->keys[i] = key; */
/*         request->command->klcommand->header->size += */
/*             key->keysize + sizeof(uint16_t) + sizeof(uint8_t); */
/*         i++; */
/*     } */
/*  */
/*     return request; */
/* } */
/*  */
/* #<{(|******************************************* */
/*  *         RESPONSE PACKING FUNCTIONS */
/*  *******************************************|)}># */
/*  */
/* void pack_response(struct buffer *b, const struct response *r) { */
/*  */
/*     assert(b && r); */
/*  */
/*     switch (r->restype) { */
/*         case NO_CONTENT: */
/*             pack_header(r->ncontent->header, b); */
/*             pack_u8(b, r->ncontent->code); */
/*             break; */
/*         case DATA_CONTENT: */
/*             pack_header(r->dcontent->header, b); */
/*             // Mandatory fields */
/*             pack_u32(b, r->dcontent->datalen); */
/*             pack_bytes(b, r->dcontent->data); */
/*             break; */
/*         case VALUE_CONTENT: */
/*             pack_header(r->vcontent->header, b); */
/*             // Mandatory fields */
/*             pack_u32(b, r->vcontent->val); */
/*             break; */
/*         case LIST_CONTENT: */
/*             pack_header(r->lcontent->header, b); */
/*             pack_u16(b, r->lcontent->len); */
/*  */
/*             for (int i = 0; i < r->lcontent->len; i++) { */
/*                 pack_u16(b, r->lcontent->keys[i]->keysize); */
/*                 pack_bytes(b, r->lcontent->keys[i]->key); */
/*                 pack_u8(b, r->lcontent->keys[i]->is_prefix); */
/*             } */
/*             break; */
/*         case KVLIST_CONTENT: */
/*             pack_header(r->kvlcontent->header, b); */
/*             pack_u16(b, r->kvlcontent->len); */
/*  */
/*             for (int i = 0; i < r->kvlcontent->len; i++) { */
/*                 pack_u16(b, r->kvlcontent->pairs[i]->keysize); */
/*                 pack_u32(b, r->kvlcontent->pairs[i]->valsize); */
/*                 pack_bytes(b, r->kvlcontent->pairs[i]->key); */
/*                 pack_bytes(b, r->kvlcontent->pairs[i]->val); */
/*                 pack_u8(b, r->kvlcontent->pairs[i]->is_prefix); */
/*             } */
/*             break; */
/*         default: */
/*             fprintf(stderr, "Pack response: not implemented yet"); */
/*             break; */
/*     } */
/* } */
/*  */
/*  */
/* struct response *unpack_response(struct buffer *b) { */
/*  */
/*     assert(b); */
/*  */
/*     struct response *response = tmalloc(sizeof(*response)); */
/*     if (!response) */
/*         return NULL; */
/*  */
/*     struct header *header = tmalloc(sizeof(*header)); */
/*     if (!header) */
/*         goto errnomem2; */
/*  */
/*     unpack_header(b, header); */
/*  */
/*     // XXX not implemented all responses yet */
/*     int8_t ctype = get_command_type(header->opcode); */
/*     response->restype = get_content_type(header->opcode); */
/*  */
/*     switch (ctype) { */
/*  */
/*         case EMPTY_COMMAND: */
/*             response->ncontent = tmalloc(sizeof(struct no_content)); */
/*             response->ncontent->header = header; */
/*             response->ncontent->code = unpack_u8(b); */
/*             break; */
/*  */
/*         case KEY_COMMAND: */
/*             response->dcontent = tmalloc(sizeof(struct data_content)); */
/*             response->dcontent->header = header; */
/*             response->dcontent->datalen = unpack_u32(b); */
/*             response->dcontent->data = */
/*                 unpack_bytes(b, response->dcontent->datalen); */
/*             break; */
/*  */
/*         case KEY_VAL_COMMAND: */
/*             // TODO */
/*             break; */
/*  */
/*         case KEY_VAL_LIST_COMMAND: */
/*             response->kvlcontent = tmalloc(sizeof(struct kvlist_content)); */
/*             response->kvlcontent->header = header; */
/*             response->kvlcontent->len = unpack_u16(b); */
/*             response->kvlcontent->pairs = */
/*                 tmalloc(response->kvlcontent->len * sizeof(struct keyval)); */
/*  */
/*             if (!response->kvlcontent->pairs) */
/*                 goto errnomem1; */
/*  */
/*             for (int i = 0; i < response->kvlcontent->len; i++) { */
/*                 struct keyval *kv = tmalloc(sizeof(*kv)); */
/*                 kv->keysize = unpack_u16(b); */
/*                 kv->valsize = unpack_u32(b); */
/*                 kv->key = unpack_bytes(b, kv->keysize); */
/*                 kv->val = unpack_bytes(b, kv->valsize); */
/*                 kv->is_prefix = unpack_u8(b); */
/*                 response->kvlcontent->pairs[i] = kv; */
/*             } */
/*  */
/*             break; */
/*     } */
/*  */
/*     return response; */
/*  */
/* errnomem1: */
/*  */
/*     tfree(header); */
/*  */
/* errnomem2: */
/*  */
/*     tfree(response); */
/*     return NULL; */
/* } */
/*  */
/*  */
/* void free_response(struct response *response) { */
/*  */
/*     if (!response) */
/*         return; */
/*  */
/*     switch (response->restype) { */
/*         case NO_CONTENT: */
/*             tfree(response->ncontent->header); */
/*             tfree(response->ncontent); */
/*             break; */
/*         case DATA_CONTENT: */
/*             tfree(response->dcontent->header); */
/*             tfree(response->dcontent->data); */
/*             tfree(response->dcontent); */
/*             break; */
/*         case VALUE_CONTENT: */
/*             tfree(response->vcontent->header); */
/*             tfree(response->vcontent); */
/*             break; */
/*         case LIST_CONTENT: */
/*             tfree(response->lcontent->header); */
/*             for (int i = 0; i < response->lcontent->len; i++) { */
/*                 tfree(response->lcontent->keys[i]->key); */
/*                 tfree(response->lcontent->keys[i]); */
/*             } */
/*             tfree(response->lcontent->keys); */
/*             tfree(response->lcontent); */
/*             break; */
/*         case KVLIST_CONTENT: */
/*             tfree(response->kvlcontent->header); */
/*             for (int i = 0; i < response->kvlcontent->len; i++) { */
/*                 tfree(response->kvlcontent->pairs[i]->key); */
/*                 tfree(response->kvlcontent->pairs[i]->val); */
/*                 tfree(response->kvlcontent->pairs[i]); */
/*             } */
/*             tfree(response->kvlcontent->pairs); */
/*             tfree(response->kvlcontent); */
/*             break; */
/*         default: */
/*             fprintf(stderr, "Free response: not implemented yet"); */
/*             break; */
/*     } */
/*  */
/*     tfree(response); */
/* } */
/*  */
/* #<{(|******************************************* */
/*  *             RESPONSE HELPERS */
/*  *******************************************|)}># */
/*  */
/* struct response *make_ack_response(uint8_t code, */
/*                                    const uint8_t *transaction_id, */
/*                                    uint8_t flags) { */
/*  */
/*     struct response *response = tmalloc(sizeof(*response)); */
/*     if (!response) */
/*         goto errnomem3; */
/*  */
/*     response->ncontent = tmalloc(sizeof(struct no_content)); */
/*     if (!response->ncontent) */
/*         goto errnomem2; */
/*  */
/*     response->ncontent->header = tmalloc(sizeof(struct header)); */
/*     if (!response->ncontent->header) */
/*         goto errnomem1; */
/*  */
/*     ack_response_init(response, code, flags, (const char *) transaction_id); */
/*  */
/*     return response; */
/*  */
/* errnomem1: */
/*  */
/*     tfree(response->ncontent); */
/*  */
/* errnomem2: */
/*  */
/*     tfree(response); */
/*  */
/* errnomem3: */
/*  */
/*     return NULL; */
/* } */
/*  */
/*  */
/* struct response *make_data_response(const uint8_t *data, */
/*                                     const uint8_t *transaction_id, */
/*                                     uint8_t flags) { */
/*  */
/*     struct response *response = tmalloc(sizeof(*response)); */
/*     if (!response) */
/*         goto errnomem3; */
/*  */
/*     response->dcontent = tmalloc(sizeof(struct data_content)); */
/*     if (!response->dcontent) */
/*         goto errnomem2; */
/*  */
/*     response->dcontent->header = tmalloc(sizeof(struct header)); */
/*     if (!response->dcontent->header) */
/*         goto errnomem1; */
/*  */
/*     data_response_init(response, data, flags, (const char *) transaction_id); */
/*  */
/*     return response; */
/*  */
/* errnomem1: */
/*  */
/*     tfree(response->dcontent); */
/*  */
/* errnomem2: */
/*  */
/*     tfree(response); */
/*  */
/* errnomem3: */
/*  */
/*     return NULL; */
/* } */
/*  */
/*  */
/* struct response *make_valuecontent_response(uint32_t value, */
/*                                             const uint8_t *transaction_id, */
/*                                             uint8_t flags) { */
/*  */
/*     struct response *response = tmalloc(sizeof(*response)); */
/*     if (!response) */
/*         goto errnomem3; */
/*  */
/*     response->vcontent = tmalloc(sizeof(struct value_content)); */
/*     if (!response->vcontent) */
/*         goto errnomem2; */
/*  */
/*     response->vcontent->header = tmalloc(sizeof(struct header)); */
/*     if (!response->vcontent->header) */
/*         goto errnomem1; */
/*  */
/*     value_response_init(response, value, flags, (const char *) transaction_id); */
/*  */
/*     return response; */
/*  */
/* errnomem1: */
/*  */
/*     tfree(response->vcontent); */
/*  */
/* errnomem2: */
/*  */
/*     tfree(response); */
/*  */
/* errnomem3: */
/*  */
/*     return NULL; */
/* } */
/*  */
/*  */
/* struct response *make_list_response(const List *content, */
/*                                     const uint8_t *transaction_id, */
/*                                     uint8_t flags) { */
/*  */
/*     struct response *response = tmalloc(sizeof(*response)); */
/*     if (!response) */
/*         return NULL; */
/*  */
/*     response->restype = LIST_CONTENT; */
/*     response->lcontent = tmalloc(sizeof(struct list_content)); */
/*     if (!response->lcontent) { */
/*         tfree(response); */
/*         return NULL; */
/*     } */
/*  */
/*     response->lcontent->header = tmalloc(sizeof(struct header)); */
/*     if (!response->lcontent->header) { */
/*         tfree(response->lcontent); */
/*         tfree(response); */
/*         return NULL; */
/*     } */
/*  */
/*     header_init(response->lcontent->header, ACK, */
/*                 HEADERLEN + sizeof(uint16_t), flags, (const char *) transaction_id); */
/*  */
/*     response->lcontent->len = content->len; */
/*     response->lcontent->keys = tcalloc(content->len, sizeof(struct key)); */
/*  */
/*     int i = 0; */
/*  */
/*     for (struct list_node *cur = content->head; cur; cur = cur->next) { */
/*         struct key *key = tmalloc(sizeof(*key)); */
/*         key->key = (uint8_t *) tstrdup((const char *) cur->data); */
/*         key->keysize = strlen((const char *) cur->data); */
/*         response->lcontent->keys[i] = key; */
/*         response->lcontent->header->size += */
/*             key->keysize + sizeof(uint16_t) + sizeof(uint8_t); */
/*         i++; */
/*     } */
/*  */
/*     return response; */
/* } */
/*  */
/*  */
/* struct response *make_kvlist_response(const List *content, */
/*                                       const uint8_t *transaction_id, */
/*                                       uint8_t flags) { */
/*  */
/*     struct response *response = tmalloc(sizeof(*response)); */
/*     if (!response) */
/*         return NULL; */
/*  */
/*     response->restype = KEY_VAL_LIST_COMMAND; */
/*     response->kvlcontent = tmalloc(sizeof(struct kvlist_content)); */
/*     if (!response->kvlcontent) { */
/*         tfree(response); */
/*         return NULL; */
/*     } */
/*  */
/*     response->kvlcontent->header = tmalloc(sizeof(struct header)); */
/*     if (!response->kvlcontent->header) { */
/*         tfree(response->kvlcontent); */
/*         tfree(response); */
/*         return NULL; */
/*     } */
/*  */
/*     header_init(response->kvlcontent->header, CLUSTER_MEMBERS, */
/*                 HEADERLEN + sizeof(uint16_t), flags, (const char *) transaction_id); */
/*  */
/*     response->kvlcontent->len = content->len; */
/*     response->kvlcontent->pairs = */
/*         tmalloc(content->len * sizeof(struct keyval)); */
/*  */
/*     int i = 0; */
/*  */
/*     for (struct list_node *cur = content->head; cur; cur = cur->next) { */
/*         struct keyval *nodekv = cur->data; */
/*         struct keyval *kv = tmalloc(sizeof(*kv)); */
/*         kv->key = (uint8_t *) tstrdup((const char *) nodekv->key); */
/*         kv->keysize = nodekv->keysize; */
/*         kv->val = (uint8_t *) tstrdup((const char *) nodekv->val); */
/*         kv->valsize = nodekv->valsize; */
/*         kv->is_prefix = 0; */
/*         response->kvlcontent->pairs[i] = kv; */
/*         response->kvlcontent->header->size += kv->keysize + kv->valsize + */
/*             sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t); */
/*         i++; */
/*     } */
/*  */
/*     return response; */
/* } */
/*  */
/*  */
/* void ack_response_init(struct response *response, */
/*                        uint8_t code, int flags, const char *transaction_id) { */
/*  */
/*     response->restype = NO_CONTENT; */
/*  */
/*     header_init(response->ncontent->header, */
/*                 ACK, HEADERLEN + sizeof(uint8_t), flags, transaction_id); */
/*  */
/*     response->ncontent->code = code; */
/* } */
/*  */
/*  */
/* void data_response_init(struct response *response, */
/*                         const uint8_t *data, uint8_t flags, */
/*                         const char *transaction_id) { */
/*  */
/*     response->restype = DATA_CONTENT; */
/*  */
/*     uint32_t len = HEADERLEN + sizeof(uint32_t) + strlen((char *) data); */
/*     header_init(response->dcontent->header, GET, len, flags, transaction_id); */
/*  */
/*     response->dcontent->datalen = strlen((char *) data); */
/*     response->dcontent->data = (uint8_t *) tstrdup((const char *) data); */
/* } */
/*  */
/*  */
/* void value_response_init(struct response *response, */
/*                          uint32_t value, uint8_t flags, */
/*                          const char *transaction_id) { */
/*  */
/*     response->restype = VALUE_CONTENT; */
/*  */
/*     header_init(response->vcontent->header, ACK, */
/*                 HEADERLEN + sizeof(uint32_t), flags, transaction_id); */
/*  */
/*     response->vcontent->val = value; */
/* } */
