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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "util.h"
#include "protocol.h"


static void pack_header(Header *, Buffer *);
static void unpack_header(Buffer *, Header *);


/* Init Buffer data structure, to ease byte arrays handling */
Buffer *buffer_init(size_t len) {
    Buffer *b = t_malloc(sizeof(Buffer));
    b->data = t_malloc(len);
    if (!b || !b->data)
        oom("allocating memory for new buffer");
    b->size = len;
    b->pos = 0;
    return b;
}


/* Destroy a previously allocated Buffer structure */
void buffer_destroy(Buffer *b) {
    assert(b && b->data);
    b->size = b->pos = 0;
    t_free(b->data);
    t_free(b);
}


// Reading data
uint8_t read_uint8(Buffer *b) {
    if ((b->pos + sizeof(uint8_t)) > b->size)
        return 0;
    uint8_t val = *(b->data + b->pos);
    b->pos += sizeof(uint8_t);
    return val;
}


uint16_t read_uint16(Buffer *b) {
    if ((b->pos + sizeof(uint16_t)) > b->size)
        return 0;
    uint16_t val = ntohs(*((uint16_t *) (b->data + b->pos)));
    b->pos += sizeof(uint16_t);
    return val;
}


uint32_t read_uint32(Buffer *b) {
    if ((b->pos + sizeof(uint32_t)) > b->size)
        return 0;
    uint32_t val = ntohl(*((uint32_t *) (b->data + b->pos)));
    b->pos += sizeof(uint32_t);
    return val;
}


uint8_t *read_string(Buffer *b, size_t len) {
    if ((b->pos + len) > b->size)
        return NULL;
    uint8_t *str = t_malloc(len + 1);
    memcpy(str, b->data + b->pos, len);
    str[len] = '\0';
    b->pos += len;
    return str;
}


// Write data
void write_uint8(Buffer *b, uint8_t val) {
    if ((b->pos + sizeof(uint8_t)) > b->size)
        return;
    *(b->data + b->pos) = val;
    b->pos += sizeof(uint8_t);
}


void write_uint16(Buffer *b, uint16_t val) {
    if ((b->pos + sizeof(uint16_t)) > b->size)
        return;
    *((uint16_t *) (b->data + b->pos)) = htons(val);
    b->pos += sizeof(uint16_t);
}


void write_uint32(Buffer *b, uint32_t val) {
    if ((b->pos + sizeof(uint32_t)) > b->size)
        return;
    *((uint32_t *) (b->data + b->pos)) = htonl(val);
    b->pos += sizeof(uint32_t);
}


void write_string(Buffer *b, uint8_t *str) {
    size_t len = strlen((char *) str);
    if ((b->pos + len) > b->size)
        return;
    memcpy(b->data + b->pos, str, len);
    b->pos += len;
}


static void pack_header(Header *h, Buffer *b) {

    assert(b && h);

    write_uint8(b, h->opcode);
    write_uint32(b, b->size);
}


static void unpack_header(Buffer *b, Header *h) {

    assert(b && h);

    h->opcode = read_uint8(b);
    h->size = read_uint32(b);
}

// Refactoring
int opcode_req_map[7][2] = {
    {PUT, KEY_VAL_COMMAND},
    {GET, KEY_COMMAND},
    {DEL, LIST_COMMAND},
    {EXP, KEY_COMMAND},
    {INC, KEY_COMMAND},
    {DEC, KEY_COMMAND}
};

/* Main unpacking function, to translates bytes received from clients to a
   packet structure, based on the opcode */
Request *unpack_request(uint8_t opcode, Buffer *b) {

    assert(b);

    Request *r = t_malloc(sizeof(*r));
    if (!r)
        return NULL;

    Header *header = t_malloc(sizeof(*header));
    if (!header)
        return NULL;

    unpack_header(b, header);

    // TODO write a more efficient solution for this hack
    int code = 0;

    for (int i = 0; i < 7; i++)
        if (opcode_req_map[i][0] == opcode)
            code = opcode_req_map[i][1];

    switch (code) {
        case KEY_COMMAND:
            r->kcommand = t_malloc(sizeof(KeyCommand));
            r->kcommand->header = header;

            // Mandatory fields
            r->kcommand->keysize = read_uint16(b);
            r->kcommand->key = read_string(b, r->kcommand->keysize);

            // Optional fields
            r->kcommand->is_prefix = read_uint8(b);
            r->kcommand->ttl = read_uint16(b);

            break;

        case KEY_VAL_COMMAND:
            r->kvcommand = t_malloc(sizeof(KeyValCommand));
            r->kvcommand->header = header;

            // Mandatory fields
            r->kvcommand->keysize = read_uint16(b);
            r->kvcommand->valsize = read_uint32(b);
            r->kvcommand->key = read_string(b, r->kvcommand->keysize);
            r->kvcommand->val = read_string(b, r->kvcommand->valsize);

            // Optional fields
            r->kvcommand->is_prefix = read_uint8(b);
            r->kvcommand->ttl = read_uint16(b);

            break;

        case LIST_COMMAND:
            r->klcommand = t_malloc(sizeof(KeyListCommand));
            r->klcommand->header = header;

            // Number of keys, or length of the Key array
            r->klcommand->len = read_uint16(b);

            r->klcommand->keys = t_calloc(r->klcommand->len, sizeof(struct Key));

            for (int i = 0; i < r->klcommand->len; i++) {
                struct Key *key = t_malloc(sizeof(*key));
                key->keysize = read_uint16(b);
                key->key = read_string(b, key->keysize);
                key->is_prefix = read_uint8(b);
                r->klcommand->keys[i] = key;
            }

            break;

        default:
            t_free(header);
            t_free(r);
            r = NULL;
            break;
    };

    return r;
}


void free_request(Request *request, uint8_t reqtype) {

    if (!request)
        return;

    switch (reqtype) {
        case KEY_COMMAND:
            t_free(request->kcommand->header);
            t_free(request->kcommand->key);
            t_free(request->kcommand);
            break;
        case KEY_VAL_COMMAND:
            t_free(request->kvcommand->header);
            t_free(request->kvcommand->key);
            t_free(request->kvcommand->val);
            t_free(request->kvcommand);
            break;
        case LIST_COMMAND:
            t_free(request->klcommand->header);
            for (int i = 0; i < request->klcommand->len; i++) {
                t_free(request->klcommand->keys[i]->key);
                t_free(request->klcommand->keys[i]);
            }
            t_free(request->klcommand->keys);
            t_free(request->klcommand);
            break;
    }

    t_free(request);
}


void pack_response(Buffer *b, Response *r, int restype) {

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
            write_string(b, r->dcontent->data);
            break;
        case VALUE_CONTENT:
            pack_header(r->vcontent->header, b);
            // Mandatory fields
            write_uint32(b, r->vcontent->val);
            break;
        case LIST_CONTENT:
            pack_header(r->lcontent->header, b);

            write_uint16(b, r->lcontent->len);

            for (int i = 0; i < r->lcontent->len; i++) {
                write_uint16(b, r->lcontent->keys[i]->keysize);
                write_string(b, r->lcontent->keys[i]->key);
                write_uint16(b, r->lcontent->keys[i]->is_prefix);
            }
            break;
    }
}


Response *make_nocontent_response(uint8_t code) {

    Response *response = t_malloc(sizeof(*response));
    if (!response)
        return NULL;

    response->ncontent = t_malloc(sizeof(NoContent));
    if (!response->ncontent) {
        t_free(response);
        return NULL;
    }

    response->ncontent->header = t_malloc(sizeof(Header));
    if (!response->ncontent->header) {
        t_free(response->ncontent);
        t_free(response);
        return NULL;
    }

    response->ncontent->header->opcode = code;
    response->ncontent->header->size = HEADERLEN + sizeof(uint8_t);

    response->ncontent->code = code;

    return response;
}


Response *make_datacontent_response(uint8_t *data) {

    Response *response = t_malloc(sizeof(*response));
    if (!response)
        return NULL;

    response->dcontent = t_malloc(sizeof(DataContent));
    if (!response->dcontent) {
        t_free(response);
        return NULL;
    }

    response->dcontent->header = t_malloc(sizeof(Header));
    if (!response->dcontent->header) {
        t_free(response->dcontent);
        t_free(response);
        return NULL;
    }

    response->dcontent->header->opcode = PUT;
    response->dcontent->header->size =
        HEADERLEN + sizeof(uint32_t) + strlen((char *) data);

    response->dcontent->datalen = strlen((char *) data);
    response->dcontent->data = (uint8_t *) strdup((const char *) data);

    return response;
}


Response *make_valuecontent_response(uint32_t value) {

    Response *response = t_malloc(sizeof(*response));
    if (!response)
        return NULL;

    response->vcontent = t_malloc(sizeof(ValueContent));
    if (!response->vcontent) {
        t_free(response);
        return NULL;
    }

    response->ncontent->header = t_malloc(sizeof(Header));
    if (!response->ncontent->header) {
        t_free(response->ncontent);
        t_free(response);
        return NULL;
    }

    response->vcontent->header->opcode = ACK;
    response->vcontent->header->size = HEADERLEN + sizeof(uint32_t);

    response->vcontent->val = value;

    return response;
}


void free_response(Response *response, int restype) {

    if (!response)
        return;

    switch (restype) {
        case NO_CONTENT:
            t_free(response->ncontent->header);
            t_free(response->ncontent);
            break;
        case DATA_CONTENT:
            t_free(response->dcontent->header);
            t_free(response->dcontent->data);
            t_free(response->dcontent);
            break;
        case VALUE_CONTENT:
            t_free(response->vcontent->header);
            t_free(response->vcontent);
            break;
        case LIST_CONTENT:
            t_free(response->lcontent->header);
            for (int i = 0; i < response->lcontent->len; i++) {
                t_free(response->lcontent->keys[i]->key);
                t_free(response->lcontent->keys[i]);
            }
            t_free(response->lcontent->keys);
            t_free(response->lcontent);
            break;
    }

    t_free(response);
}
