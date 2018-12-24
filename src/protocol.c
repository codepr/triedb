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
Buffer *buffer_init(const size_t len) {
    Buffer *b = malloc(sizeof(Buffer));
    b->data = malloc(len);
    if (!b || !b->data) oom("allocating memory for new buffer");
    b->size = len;
    b->pos = 0;
    return b;
}


/* Destroy a previously allocated Buffer structure */
void buffer_destroy(Buffer *b) {
    assert(b);
    assert(b->data);
    b->size = b->pos = 0;
    free(b->data);
    free(b);
}


// Reading data
uint8_t read_uint8(Buffer *b) {
    uint8_t val = *(b->data + b->pos);
    b->pos += sizeof(uint8_t);
    return val;
}


uint16_t read_uint16(Buffer *b) {
    uint16_t val = ntohs(*((uint16_t *) (b->data + b->pos)));
    b->pos += sizeof(uint16_t);
    return val;
}


uint32_t read_uint32(Buffer *b) {
    uint32_t val = ntohl(*((uint32_t *) (b->data + b->pos)));
    b->pos += sizeof(uint32_t);
    return val;
}


uint8_t *read_string(Buffer *b, size_t len) {
    uint8_t *str = malloc(len + 1);
    memcpy(str, b->data + b->pos, len);
    str[len] = '\0';
    b->pos += len;
    return str;
}


// Write data
void write_uint8(Buffer *b, uint8_t val) {
    *(b->data + b->pos) = val;
    b->pos += sizeof(uint8_t);
}


void write_uint16(Buffer *b, uint16_t val) {
    *((uint16_t *) (b->data + b->pos)) = htons(val);
    b->pos += sizeof(uint16_t);
}


void write_uint32(Buffer *b, uint32_t val) {
    *((uint32_t *) (b->data + b->pos)) = htonl(val);
    b->pos += sizeof(uint32_t);
}


void write_string(Buffer *b, uint8_t *str) {
    size_t len = strlen((char *) str);
    memcpy(b->data + b->pos, str, len);
    b->pos += len;
}


static void pack_header(Header *h, Buffer *b) {

    assert(b);
    assert(h);

    write_uint8(b, h->opcode);
    write_uint32(b, b->size);
}


static void unpack_header(Buffer *b, Header *h) {

    assert(b);
    assert(h);

    h->opcode = read_uint8(b);
    h->size = read_uint32(b);
}


int8_t unpack_put(Buffer *b, Put *p) {

    assert(b);
    assert(p);

    /* Start unpacking bytes into the Request structure */

    p->header = malloc(sizeof(Header));
    if (!p->header)
        return -EOOM;

    unpack_header(b, p->header);

    p->keysize = read_uint16(b);
    p->valsize = read_uint32(b);
    p->key = read_string(b, p->keysize);
    p->value = read_string(b, p->valsize);

    return OK;
}


int8_t unpack_get(Buffer *b, Get *g) {

    assert(b);
    assert(g);

    /* Start unpacking bytes into the Request structure */

    g->header = malloc(sizeof(Header));
    if (!g->header)
        return -EOOM;

    unpack_header(b, g->header);

    g->keysize = read_uint16(b);
    g->key = read_string(b, g->keysize);

    return OK;
}


int8_t unpack_del(Buffer *b, Del *d) {

    assert(b);
    assert(d);

    /* Start unpacking bytes into the Request structure */

    d->header = malloc(sizeof(Header));
    if (!d->header)
        return -EOOM;

    unpack_header(b, d->header);

    d->keysize = read_uint16(b);
    d->key = read_string(b, d->keysize);

    return OK;
}


int8_t unpack_exp(Buffer *b, Exp *e) {

    assert(b);
    assert(e);

    /* Start unpacking bytes into the Request structure */

    e->header = malloc(sizeof(Header));
    if (!e->header)
        return -EOOM;

    unpack_header(b, e->header);

    e->keysize = read_uint16(b);
    e->key = read_string(b, e->keysize);
    e->ttl = read_uint16(b);

    return OK;
}


void pack_put(Buffer *b, Put *pkt) {

    assert(b);
    assert(pkt);

    pack_header(pkt->header, b);

    write_uint16(b, pkt->keysize);
    write_uint32(b, pkt->valsize);
    write_string(b, pkt->key);
    write_string(b, pkt->value);
}


void pack_get(Buffer *b, Get *pkt) {

    assert(b);
    assert(pkt);

    pack_header(pkt->header, b);

    write_uint16(b, pkt->keysize);
    write_string(b, pkt->key);
}


void pack_del(Buffer *b, Del *pkt) {

    assert(b);
    assert(pkt);

    pack_header(pkt->header, b);

    write_uint16(b, pkt->keysize);
    write_string(b, pkt->key);
}


void pack_exp(Buffer *b, Exp *pkt) {

    assert(b);
    assert(pkt);

    pack_header(pkt->header, b);

    write_uint16(b, pkt->keysize);
    write_string(b, pkt->key);
    write_uint16(b, pkt->ttl);
}


void pack_ack(Buffer *b, Ack *pkt) {

    assert(b);
    assert(pkt);

    pack_header(pkt->header, b);

    write_uint8(b, pkt->code);
}


Ack *ack_packet(uint8_t code) {

    Ack *pkt = malloc(sizeof(Ack));
    if (!pkt) oom("building subscribe request");

    pkt->header = malloc(sizeof(Header));
    if (!pkt->header) oom("building header of subscribe request");

    pkt->header->opcode = ACK;
    pkt->header->size = HEADERLEN + sizeof(uint8_t);
    pkt->code = code;

    return pkt;
}


Nack *nack_packet(uint8_t code) {

    Nack *pkt = malloc(sizeof(Ack));
    if (!pkt) oom("building subscribe request");

    pkt->header = malloc(sizeof(Header));
    if (!pkt->header) oom("building header of subscribe request");

    pkt->header->opcode = NACK;
    pkt->header->size = HEADERLEN + sizeof(uint8_t);
    pkt->code = code;

    return pkt;

}


Put *put_packet(uint8_t *key, uint8_t *value) {

    assert(key);
    assert(value);

    Put *pkt = malloc(sizeof(*pkt));
    if (!pkt) oom("building unsubscribe request");

    pkt->header = malloc(sizeof(Header));
    if (!pkt->header) oom("building unsubscribe header");

    pkt->header->opcode = PUT;
    pkt->header->size = HEADERLEN + strlen((char *) key) +
        strlen((char *) value) + sizeof(uint16_t) + sizeof(uint32_t);
    pkt->keysize = strlen((char *) key);
    pkt->valsize = strlen((char *) value);
    pkt->key = (uint8_t *) strdup((const char *) key);
    pkt->value = (uint8_t *) strdup((const char *) value);

    return pkt;
}



void free_put(Put **p) {
    if (!*p)
        return;
    if ((*p)->header) {
        free((*p)->header);
        (*p)->header = NULL;
    }
    if ((*p)->key) {
        free((*p)->key);
        (*p)->key = NULL;
    }
    if ((*p)->value) {
        free((*p)->value);
        (*p)->value = NULL;
    }
    free(*p);
    *p = NULL;
}


void free_get(Get **g) {
    if (!*g)
        return;
    if ((*g)->header) {
        free((*g)->header);
        (*g)->header = NULL;
    }
    if ((*g)->key) {
        free((*g)->key);
        (*g)->key = NULL;
    }
    free(*g);
    *g = NULL;
}


void free_exp(Exp **e) {
    if (!*e)
        return;
    if ((*e)->header) {
        free((*e)->header);
        (*e)->header = NULL;
    }
    if ((*e)->key) {
        free((*e)->key);
        (*e)->key = NULL;
    }
    free(*e);
    *e = NULL;
}


void free_del(Del **d) {
    if (!*d)
        return;
    if ((*d)->header) {
        free((*d)->header);
        (*d)->header = NULL;
    }
    if ((*d)->key) {
        free((*d)->key);
        (*d)->key = NULL;
    }
    free(*d);
    *d = NULL;
}


void free_ack(Ack **a) {
    if (!*a)
        return;
    if ((*a)->header) {
        free((*a)->header);
        (*a)->header = NULL;
    }
    free(*a);
    *a = NULL;
}
