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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "util.h"
#include "protocol.h"


static void pack_header(const struct header *, struct buffer *);
static void unpack_header(struct buffer *, struct header *);


/* Host-to-network (native endian to big endian) */
void htonll(uint8_t *block, uint_least64_t num) {
    block[0] = num >> 56 & 0xFF;
    block[1] = num >> 48 & 0xFF;
    block[2] = num >> 40 & 0xFF;
    block[3] = num >> 32 & 0xFF;
    block[4] = num >> 24 & 0xFF;
    block[5] = num >> 16 & 0xFF;
    block[6] = num >> 8 & 0xFF;
    block[7] = num >> 0 & 0xFF;
}

/* Network-to-host (big endian to native endian) */
uint_least64_t ntohll(const uint8_t *block) {
    return (uint_least64_t) block[0] << 56 |
        (uint_least64_t) block[1] << 48 |
        (uint_least64_t) block[2] << 40 |
        (uint_least64_t) block[3] << 32 |
        (uint_least64_t) block[4] << 24 |
        (uint_least64_t) block[5] << 16 |
        (uint_least64_t) block[6] << 8 |
        (uint_least64_t) block[7] << 0;
}

/* Init struct buffer data structure, to ease byte arrays handling */
struct buffer *buffer_init(size_t len) {
    struct buffer *b = tmalloc(sizeof(struct buffer));
    b->data = tmalloc(len);
    if (!b || !b->data)
        oom("allocating memory for new buffer");
    b->size = len;
    b->pos = 0;
    return b;
}


/* Destroy a previously allocated struct buffer structure */
void buffer_destroy(struct buffer *b) {
    assert(b && b->data);
    b->size = b->pos = 0;
    tfree(b->data);
    tfree(b);
}


// Reading data
uint8_t read_uint8(struct buffer *b) {
    if ((b->pos + sizeof(uint8_t)) > b->size)
        return 0;
    uint8_t val = *(b->data + b->pos);
    b->pos += sizeof(uint8_t);
    return val;
}


uint16_t read_uint16(struct buffer *b) {
    if ((b->pos + sizeof(uint16_t)) > b->size)
        return 0;
    uint16_t val = ntohs(*((uint16_t *) (b->data + b->pos)));
    b->pos += sizeof(uint16_t);
    return val;
}


uint32_t read_uint32(struct buffer *b) {
    if ((b->pos + sizeof(uint32_t)) > b->size)
        return 0;
    uint32_t val = ntohl(*((uint32_t *) (b->data + b->pos)));
    b->pos += sizeof(uint32_t);
    return val;
}


uint64_t read_uint64(struct buffer *b) {
    if ((b->pos + sizeof(uint64_t)) > b->size)
        return 0;
    uint64_t val = ntohll(b->data + b->pos);
    b->pos += sizeof(uint64_t);
    return val;
}


uint8_t *read_bytes(struct buffer *b, size_t len) {
    if ((b->pos + len) > b->size)
        return NULL;
    uint8_t *str = tmalloc(len + 1);
    memcpy(str, b->data + b->pos, len);
    str[len] = '\0';
    b->pos += len;
    return str;
}


// Write data
void write_uint8(struct buffer *b, uint8_t val) {
    if ((b->pos + sizeof(uint8_t)) > b->size)
        return;
    *(b->data + b->pos) = val;
    b->pos += sizeof(uint8_t);
}


void write_uint16(struct buffer *b, uint16_t val) {
    if ((b->pos + sizeof(uint16_t)) > b->size)
        return;
    *((uint16_t *) (b->data + b->pos)) = htons(val);
    b->pos += sizeof(uint16_t);
}


void write_uint32(struct buffer *b, uint32_t val) {
    if ((b->pos + sizeof(uint32_t)) > b->size)
        return;
    *((uint32_t *) (b->data + b->pos)) = htonl(val);
    b->pos += sizeof(uint32_t);
}


void write_uint64(struct buffer *b, uint64_t val) {
    if ((b->pos + sizeof(uint64_t)) > b->size)
        return;
    htonll(b->data + b->pos, val);
    b->pos += sizeof(uint64_t);
}


void write_bytes(struct buffer *b, uint8_t *str) {
    size_t len = strlen((char *) str);
    if ((b->pos + len) > b->size)
        return;
    memcpy(b->data + b->pos, str, len);
    b->pos += len;
}


static void pack_header(const struct header *h, struct buffer *b) {

    assert(b && h);

    write_uint8(b, h->opcode);
    write_uint32(b, b->size);
    write_uint8(b, h->flags & F_BULKREQUEST ? 1 : 0);
    write_uint8(b, h->flags & F_PREFIXREQUEST ? 1 : 0);
    write_uint8(b, h->flags & F_FROMNODEREQUEST ? 1 : 0);
    write_uint8(b, h->flags & F_FROMNODERESPONSE ? 1 : 0);

    if ((h->flags & F_FROMNODEREQUEST) || (h->flags & F_FROMNODERESPONSE))
        write_bytes(b, (uint8_t *) h->transaction_id);
}


static void unpack_header(struct buffer *b, struct header *h) {

    assert(b && h);

    h->flags = 0;

    uint8_t is_bulk = 0, is_prefix = 0, is_fromnodereq = 0, is_fromnoderes = 0;

    h->opcode = read_uint8(b);
    h->size = read_uint32(b);

    is_bulk = read_uint8(b);
    is_prefix = read_uint8(b);
    is_fromnodereq = read_uint8(b);
    is_fromnoderes = read_uint8(b);

    if (is_bulk)
        h->flags |= F_BULKREQUEST;

    if (is_prefix)
        h->flags |= F_PREFIXREQUEST;

    if (is_fromnodereq)
        h->flags |= F_FROMNODEREQUEST;

    if (is_fromnoderes)
        h->flags |= F_FROMNODERESPONSE;

    if (is_fromnodereq || is_fromnoderes)
        strcpy(h->transaction_id, (const char *) read_bytes(b, UUID_LEN-1));
}

// Refactoring
static const int opcode_req_map[COMMAND_COUNT][2] = {
    {PUT, KEY_VAL_COMMAND},
    {GET, KEY_COMMAND},
    {DEL, KEY_LIST_COMMAND},
    {TTL, KEY_COMMAND},
    {INC, KEY_LIST_COMMAND},
    {DEC, KEY_LIST_COMMAND},
    {COUNT, KEY_COMMAND},
    {KEYS, KEY_COMMAND},
    {USE, KEY_COMMAND},
    {CLUSTER_JOIN, KEY_COMMAND},
    {PING, EMPTY_COMMAND},
    {DB, EMPTY_COMMAND},
    {INFO, EMPTY_COMMAND},
    {QUIT, EMPTY_COMMAND}
};


struct request *unpack_request(struct buffer *b) {

    assert(b);

    struct request *request = tmalloc(sizeof(*request));
    if (!request)
        return NULL;

    struct header *header = tmalloc(sizeof(*header));
    if (!header)
        goto errnomem2;

    unpack_header(b, header);

    if (!(header->flags & F_BULKREQUEST)) {
        /* It's a single request, just unpack it into the request pointer */
        request->reqtype = SINGLE_REQUEST;
        request->command = unpack_command(b, header);
    } else {
        /* Unpack the Bulkstruct request format */
        request->reqtype = BULK_REQUEST;
        request->bulk_command = tmalloc(sizeof(struct bulk_command));
        if (!request->bulk_command)
            goto errnomem1;

        uint32_t ncommands = read_uint32(b);
        request->bulk_command->ncommands = ncommands;
        request->bulk_command->commands =
            tmalloc(ncommands * sizeof(struct command));

        /* Unpack each single packet into the array of requests */
        for (uint32_t i = 0; i < ncommands; i++)
            request->bulk_command->commands[i] = unpack_command(b, header);
    }

    return request;

errnomem1:

    tfree(header);

errnomem2:

    tfree(request);
    return NULL;
}

/* Main unpacking function, to translates bytes received from clients to a
   packet structure, based on the opcode */
struct command *unpack_command(struct buffer *b, struct header *header) {

    assert(b && header);

    struct command *command = tmalloc(sizeof(*command));
    if (!command)
        return NULL;

    // TODO write a more efficient solution for this hack
    int code = 0;

    for (int i = 0; i < COMMAND_COUNT; i++)
        if (opcode_req_map[i][0] == header->opcode)
            code = opcode_req_map[i][1];

    command->cmdtype = code;

    switch (code) {
        case EMPTY_COMMAND:
            command->ecommand = tmalloc(sizeof(struct empty_command));
            if (!command->ecommand)
                goto errnomem3;

            command->ecommand->header = header;
            break;
        case KEY_COMMAND:
            command->kcommand = tmalloc(sizeof(struct key_command));
            if (!command->kcommand)
                goto errnomem3;

            command->kcommand->header = header;

            // Mandatory fields
            command->kcommand->keysize = read_uint16(b);
            command->kcommand->key = read_bytes(b, command->kcommand->keysize);

            // Optional fields
            command->kcommand->is_prefix = read_uint8(b);
            command->kcommand->ttl = read_uint16(b);

            break;

        case KEY_VAL_COMMAND:
            command->kvcommand = tmalloc(sizeof(struct keyval_command));
            if (!command->kvcommand)
                goto errnomem3;

            command->kvcommand->header = header;

            // Mandatory fields
            command->kvcommand->keysize = read_uint16(b);
            command->kvcommand->valsize = read_uint32(b);
            command->kvcommand->key =
                read_bytes(b, command->kvcommand->keysize);
            command->kvcommand->val =
                read_bytes(b, command->kvcommand->valsize);

            // Optional fields
            command->kvcommand->is_prefix = read_uint8(b);
            command->kvcommand->ttl = read_uint16(b);

            break;

        case KEY_LIST_COMMAND:
            command->klcommand = tmalloc(sizeof(struct key_list_command));
            if (!command->klcommand)
                goto errnomem3;

            command->klcommand->header = header;

            // Number of keys, or length of the Key array
            command->klcommand->len = read_uint32(b);

            command->klcommand->keys =
                tcalloc(command->klcommand->len, sizeof(struct key));

            if (!command->klcommand->keys)
                goto errnomem2;

            for (int i = 0; i < command->klcommand->len; i++) {

                struct key *key = tmalloc(sizeof(*key));
                if (!key)
                    goto errnomem1;

                key->keysize = read_uint16(b);
                key->key = read_bytes(b, key->keysize);
                key->is_prefix = read_uint8(b);
                command->klcommand->keys[i] = key;
            }

            break;

        default:
            tfree(header);
            tfree(command);
            command = NULL;
            break;
    };

    return command;

errnomem1:

    tfree(command->klcommand->keys);

errnomem2:

    tfree(command->klcommand);

errnomem3:

    tfree(command);
    return NULL;
}


static void free_header(struct command *command) {

    if (!command)
        return;

    switch (command->cmdtype) {
        case EMPTY_COMMAND:
            tfree(command->ecommand->header);
            break;
        case KEY_COMMAND:
            tfree(command->kcommand->header);
            break;
        case KEY_VAL_COMMAND:
            tfree(command->kvcommand->header);
            break;
        case KEY_LIST_COMMAND:
            tfree(command->klcommand->header);
            break;
    }
}


void free_request(struct request *request, uint8_t cmdtype) {

    if (!request)
        return;

    if (cmdtype == 0) {
        free_command(request->command, true);
    } else {

        // FIXME hack, free the first pointer
        free_header(request->bulk_command->commands[0]);
        for (int i = 0; i < request->bulk_command->ncommands; i++)
            free_command(request->bulk_command->commands[i], false);

        tfree(request->bulk_command->commands);
        tfree(request->bulk_command);
    }

    tfree(request);
}


void free_command(struct command *command, bool with_header) {

    if (!command)
        return;

    switch (command->cmdtype) {
        case EMPTY_COMMAND:
            if (with_header)
                tfree(command->ecommand->header);
            tfree(command->ecommand);
            break;
        case KEY_COMMAND:
            if (with_header)
                tfree(command->kcommand->header);
            tfree(command->kcommand->key);
            tfree(command->kcommand);
            break;
        case KEY_VAL_COMMAND:
            if (with_header)
                tfree(command->kvcommand->header);
            tfree(command->kvcommand->key);
            tfree(command->kvcommand->val);
            tfree(command->kvcommand);
            break;
        case KEY_LIST_COMMAND:
            if (with_header)
                tfree(command->klcommand->header);
            for (int i = 0; i < command->klcommand->len; i++) {
                tfree(command->klcommand->keys[i]->key);
                tfree(command->klcommand->keys[i]);
            }
            tfree(command->klcommand->keys);
            tfree(command->klcommand);
            break;
    }

    tfree(command);
}


void pack_response(struct buffer *b, const union response *r, int restype) {

    assert(b && r);

    switch (restype) {
        case NO_CONTENT:
            pack_header(r->ncontent->header, b);
            write_uint8(b, r->ncontent->code);
            break;
        case DATA_CONTENT:
            pack_header(r->dcontent->header, b);
            // Mandatory fields
            write_uint32(b, r->dcontent->datalen);
            write_bytes(b, r->dcontent->data);
            break;
        case VALUE_CONTENT:
            pack_header(r->vcontent->header, b);
            // Mandatory fields
            write_uint32(b, r->vcontent->val);
            break;
        case LIST_CONTENT:
            pack_header(r->lcontent->header, b);
            write_uint32(b, r->lcontent->len);

            for (int i = 0; i < r->lcontent->len; i++) {
                write_uint16(b, r->lcontent->keys[i]->keysize);
                write_bytes(b, r->lcontent->keys[i]->key);
                write_uint8(b, r->lcontent->keys[i]->is_prefix);
            }
            break;
    }
}


union response *make_ack_response(uint8_t code,
        const uint8_t *transaction_id, uint8_t flags) {

    union response *response = tmalloc(sizeof(*response));
    if (!response)
        goto errnomem3;

    response->ncontent = tmalloc(sizeof(struct no_content));
    if (!response->ncontent)
        goto errnomem2;

    response->ncontent->header = tmalloc(sizeof(struct header));
    if (!response->ncontent->header)
        goto errnomem1;

    response->ncontent->header->opcode = ACK;
    response->ncontent->header->size = HEADERLEN + sizeof(uint8_t);
    response->ncontent->header->flags = 0 | flags;

    if (transaction_id && (flags & F_FROMNODERESPONSE)) {
        strncpy(response->ncontent->header->transaction_id,
                (const char *) transaction_id, 37);
        response->ncontent->header->size += 37;
    }

    response->ncontent->code = code;

    return response;

errnomem1:

    tfree(response->ncontent);

errnomem2:

    tfree(response);

errnomem3:

    return NULL;
}


union response *make_data_response(const uint8_t *data,
        const uint8_t *transaction_id, uint8_t flags) {

    union response *response = tmalloc(sizeof(*response));
    if (!response)
        goto errnomem3;

    response->dcontent = tmalloc(sizeof(struct data_content));
    if (!response->dcontent)
        goto errnomem2;

    response->dcontent->header = tmalloc(sizeof(struct header));
    if (!response->dcontent->header)
        goto errnomem1;

    response->dcontent->header->opcode = PUT;
    response->dcontent->header->size =
        HEADERLEN + sizeof(uint32_t) + strlen((char *) data);
    response->dcontent->header->flags = 0 | flags;

    if (transaction_id && (flags & F_FROMNODERESPONSE)) {
        strncpy(response->dcontent->header->transaction_id,
                (const char *) transaction_id, 37);
        response->dcontent->header->size += 37;
    }

    response->dcontent->datalen = strlen((char *) data);
    response->dcontent->data = (uint8_t *) tstrdup((const char *) data);

    return response;

errnomem1:

    tfree(response->dcontent);

errnomem2:

    tfree(response);

errnomem3:

    return NULL;
}


union response *make_valuecontent_response(uint32_t value,
        const uint8_t *transaction_id, uint8_t flags) {

    union response *response = tmalloc(sizeof(*response));
    if (!response)
        goto errnomem3;

    response->vcontent = tmalloc(sizeof(struct value_content));
    if (!response->vcontent)
        goto errnomem2;

    response->vcontent->header = tmalloc(sizeof(struct header));
    if (!response->vcontent->header)
        goto errnomem1;

    response->vcontent->header->opcode = ACK;
    response->vcontent->header->size = HEADERLEN + sizeof(uint32_t);
    response->vcontent->header->flags = 0 | flags;

    if (transaction_id && (flags & F_FROMNODERESPONSE)) {
        strncpy(response->vcontent->header->transaction_id,
                (const char *) transaction_id, 37);
        response->vcontent->header->size += 37;
    }

    response->vcontent->val = value;

    return response;

errnomem1:

    tfree(response->vcontent);

errnomem2:

    tfree(response);

errnomem3:

    return NULL;
}


union response *make_list_response(const List *content,
        const uint8_t *transaction_id, uint8_t flags) {

    union response *response = tmalloc(sizeof(*response));
    if (!response)
        return NULL;

    response->lcontent = tmalloc(sizeof(struct list_content));
    if (!response->lcontent) {
        tfree(response);
        return NULL;
    }

    response->lcontent->header = tmalloc(sizeof(struct header));
    if (!response->lcontent->header) {
        tfree(response->lcontent);
        tfree(response);
        return NULL;
    }

    response->lcontent->header->opcode = ACK;
    response->lcontent->header->size = HEADERLEN + sizeof(uint32_t);
    response->lcontent->header->flags = 0 | flags;

    if (transaction_id && (flags & F_FROMNODERESPONSE)) {
        strncpy(response->lcontent->header->transaction_id,
                (const char *) transaction_id, 37);
        response->lcontent->header->size += 37;
    }

    response->lcontent->len = content->len;
    response->lcontent->keys = tcalloc(content->len, sizeof(struct key));

    int i = 0;

    for (struct list_node *cur = content->head; cur; cur = cur->next) {
        struct key *key = tmalloc(sizeof(*key));
        key->key = (uint8_t *) tstrdup((const char *) cur->data);
        key->keysize = strlen((const char *) cur->data);
        response->lcontent->keys[i] = key;
        response->lcontent->header->size +=
            key->keysize + sizeof(uint16_t) + sizeof(uint8_t);
        i++;
    }

    return response;
}


void free_response(union response *response, int restype) {

    if (!response)
        return;

    switch (restype) {
        case NO_CONTENT:
            tfree(response->ncontent->header);
            tfree(response->ncontent);
            break;
        case DATA_CONTENT:
            tfree(response->dcontent->header);
            tfree(response->dcontent->data);
            tfree(response->dcontent);
            break;
        case VALUE_CONTENT:
            tfree(response->vcontent->header);
            tfree(response->vcontent);
            break;
        case LIST_CONTENT:
            tfree(response->lcontent->header);
            for (int i = 0; i < response->lcontent->len; i++) {
                tfree(response->lcontent->keys[i]->key);
                tfree(response->lcontent->keys[i]);
            }
            tfree(response->lcontent->keys);
            tfree(response->lcontent);
            break;
    }

    tfree(response);
}


struct request *make_key_request(const uint8_t *key, uint8_t opcode,
        uint8_t is_prefix, uint16_t ttl, uint8_t flags) {

    struct request *request = tmalloc(sizeof(*request));
    if (!request)
        goto err;

    request->reqtype = SINGLE_REQUEST;
    request->command = tmalloc(sizeof(struct command));
    if (!request->command)
        goto errnomem1;

    request->command->cmdtype = KEY_COMMAND;
    request->command->kcommand = tmalloc(sizeof(struct key_command));
    if (!request->command->kcommand)
        goto errnomem2;

    request->command->kcommand->header = tmalloc(sizeof(struct header));
    if (!request->command->kcommand->header)
        goto errnomem3;

    request->command->kcommand->header->size = HEADERLEN +
        (2 * sizeof(uint16_t)) + strlen((const char *) key) + sizeof(uint8_t);

    request->command->kcommand->header->flags = 0 | flags;

    if (flags & F_FROMNODEREQUEST) {
        char uuid[UUID_LEN];
        generate_uuid(uuid);
        strcpy(request->command->kcommand->header->transaction_id, uuid);
        request->command->kcommand->header->size += UUID_LEN;
    }

    request->command->kcommand->header->opcode = opcode;

    request->command->kcommand->keysize = strlen((const char *) key);
    request->command->kcommand->key = (uint8_t *) tstrdup((const char *) key);

    request->command->kcommand->ttl = ttl;
    request->command->kcommand->is_prefix = is_prefix;

    return request;

errnomem3:

    tfree(request->command->kcommand);

errnomem2:

    tfree(request->command);

errnomem1:

    tfree(request);

err:

    return NULL;
}


void pack_request(struct buffer *buffer,
        const struct request *request, int reqtype) {

    assert(buffer && request);

    switch (reqtype) {
        case KEY_COMMAND:
            pack_header(request->command->kcommand->header, buffer);
            write_uint16(buffer, request->command->kcommand->keysize);
            write_bytes(buffer, request->command->kcommand->key);
            write_uint8(buffer, request->command->kcommand->is_prefix);
            write_uint16(buffer, request->command->kcommand->ttl);
            break;
        default:
            fprintf(stderr, "Not implemented yet\n");
            break;
    }
}
