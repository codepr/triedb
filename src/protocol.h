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

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdio.h>
#include <stdint.h>

/* Error codes */
#define OK          0x00
#define EOOM        0x01

/* Operation codes */
#define PUT         0x10
#define GET         0x20
#define DEL         0x30
#define ACK         0x40
#define NACK        0x50


/* 5 bytes to store the operation code (PUT, GET etc ...) and the total length
   of the packet */
#define HEADERLEN sizeof(uint8_t) + sizeof(uint32_t)


typedef struct {
    uint8_t opcode;
    uint32_t size;
} Header;


typedef struct {
    Header *header;
    uint16_t keysize;
    uint32_t valsize;
    uint8_t *key;
    uint8_t *value;
} Put;


typedef struct {
    Header *header;
    uint16_t keysize;
    uint8_t *key;
} Get;


typedef struct {
    Header *header;
    uint8_t code;
} Ack;


typedef Get Del;

/* Currently ACK == NACK, so to simplify we assume that they're the same */
typedef Ack Nack;


/* Buffer structure, provides a convenient way of handling byte string data.
   It is essentially an unsigned char pointer that track the position of the
   last written byte and the total size of the bystestring */
typedef struct {
    size_t size;
    size_t pos;
    uint8_t *data;
} Buffer;


Buffer *buffer_init(const size_t);
void buffer_destroy(Buffer *);


/* Reading data on Buffer pointer */
uint8_t read_uint8(Buffer *);
uint16_t read_uint16(Buffer *);
uint32_t read_uint32(Buffer *);
uint8_t *read_string(Buffer *, size_t);


/* Write data on Buffer pointer */
void write_uint8(Buffer *, uint8_t);
void write_uint16(Buffer *, uint16_t);
void write_uint32(Buffer *, uint32_t);
void write_string(Buffer *, uint8_t *);


/* Pack/Unpack functions for every specific command defined */
int8_t unpack_put(Buffer *, Put *);
int8_t unpack_get(Buffer *, Get *);
int8_t unpack_del(Buffer *, Del *);


void pack_put(Buffer *, Put *);
void pack_get(Buffer *, Get *);
void pack_del(Buffer *, Del *);
void pack_ack(Buffer *, Ack *);


/* Builder and destroy functions for every specific command defined */
Put *put_packet(uint8_t *, uint8_t *);
Ack *ack_packet(uint8_t);
Nack *nack_packet(uint8_t);


void free_put(Put **);
void free_get(Get **);
void free_del(Del **);
void free_ack(Ack **);


#endif
