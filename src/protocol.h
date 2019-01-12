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
#include "list.h"

/* Error codes */
#define OK                      0x00
#define NOK                     0x01
#define EOOM                    0x01

/* Request type */
#define SINGLE_REQUEST          0x00
#define BULK_REQUEST            0x01

/* Command type */
#define EMPTY_COMMAND           0x00
#define KEY_COMMAND             0x01
#define KEY_VAL_COMMAND         0x02
#define KEY_LIST_COMMAND        0x03
#define KEY_VAL_LIST_COMMAND    0x04

/* Response type */
#define NO_CONTENT              0x00
#define DATA_CONTENT            0x01
#define VALUE_CONTENT           0x02
#define LIST_CONTENT            0x03

#define COMMAND_COUNT           10

/* Operation codes */
#define ACK                     0x00
#define PUT                     0x01
#define GET                     0x02
#define DEL                     0x03
#define TTL                     0x04
#define INC                     0x05
#define DEC                     0x06
#define COUNT                   0x07
#define KEYS                    0x08
#define INFO                    0xfe
#define QUIT                    0xff


/* 6 bytes to store the operation code (PUT, GET etc ...) the total length of
   the packet and if it is a single command or a stream of sequential commands */
#define HEADERLEN (2 * sizeof(uint8_t)) + sizeof(uint32_t)


/* Buffer structure, provides a convenient way of handling byte string data.
   It is essentially an unsigned char pointer that track the position of the
   last written byte and the total size of the bystestring */
typedef struct {
    size_t size;
    size_t pos;
    uint8_t *data;
} Buffer;

/* Host to network byteorder for unsigned long long values, it is achieved by
   treating a single u64 as two u32 numbers */
void htonll(uint8_t *, uint_least64_t);

/* Network to host byteorder for unsigned long long values, it is achieved by
   treating a single u64 as two u32 numbers */
uint_least64_t ntohll(const uint8_t *);

// Buffer constructor, it require a size cause we use a bounded buffer, e.g.
// no resize over a defined size
Buffer *buffer_init(size_t);

void buffer_destroy(Buffer *);


/* Reading data on Buffer pointer */
// bytes -> uint8_t
uint8_t read_uint8(Buffer *);
// bytes -> uint16_t
uint16_t read_uint16(Buffer *);
// bytes -> uint32_t
uint32_t read_uint32(Buffer *);
// bytes -> uint64_t
uint64_t read_uint64(Buffer *);
// read a defined len of bytes
uint8_t *read_bytes(Buffer *, size_t);


/* Write data on Buffer pointer */
// append a uint8_t -> bytes into the buffer
void write_uint8(Buffer *, uint8_t);
// append a uint16_t -> bytes into the buffer
void write_uint16(Buffer *, uint16_t);
// append a uint32_t -> bytes into the buffer
void write_uint32(Buffer *, uint32_t);
// append a uint64_t -> bytes into the buffer
void write_uint64(Buffer *, uint64_t);
// append len bytes into the buffer
void write_bytes(Buffer *, uint8_t *);


/* Definition of the common header, for now it simply define the operation
 * code, the total size of the packet including the body and if it carry a
 * single command or a stream of sequential commands.
 */
typedef struct {
    uint8_t opcode;
    uint32_t size;
    uint8_t is_bulk;
} Header;

/* Definition of a single key, with `is_prefix` defining if the key must be
 * treated as a prefix, in other words if the command which operates on it
 * have to be used as a glob style command e.g. DEL hello* deletes all keys
 * starting with hello
 */
struct Key {
    uint16_t keysize;
    uint8_t *key;
    uint8_t is_prefix;
};

/* Definition of a key-value pair, for the rest it is equal to Key */
struct KeyVal {
    uint16_t keysize;
    uint32_t valsize;
    uint8_t *key;
    uint8_t *val;
    uint8_t is_prefix;
};

// Empty command, for those commands that doesn't require a body at all, like
// QUIT
typedef struct {
    Header *header;
} EmptyCommand;

// For all commands that does only need key field and some extra optionals
// fields like the time to live (`ttl`) or the `is_prefix` flag
// e.g. GET, TTL, INC, DEC.. etc
typedef struct {
    Header *header;
    uint16_t keysize;
    uint8_t* key;
    uint8_t is_prefix;
    uint16_t ttl;
} KeyCommand;

// For all commands that does need key and val fields with some extra optionals
// fields like the time to live (`ttl`) or the `is_prefix` flag
// e.g. PUT .. etc
typedef struct {
    Header *header;
    uint16_t keysize;
    uint32_t valsize;
    uint8_t *key;
    uint8_t *val;
    uint8_t is_prefix;
    uint16_t ttl;
} KeyValCommand;

// For all commands that does need a list of keys with some extra optionals
// fields like the time to live (`ttl`) or the `is_prefix` flag
// e.g. DEL .. etc
typedef struct {
    Header *header;
    uint32_t len;
    struct Key **keys;
} KeyListCommand;

// For commands list formed by key-value complete pairs
typedef struct {
    Header *header;
    uint16_t len;
    struct KeyValue **pairs;
} KeyValListCommand;

// Define a request, can be either an `EmptyCommand`, a `KeyCommand`, a
// `KeyValCommand` or a `KeyListCommand`
// TODO move header outside of each single command
typedef struct {
    uint8_t cmdtype;
    union {
        EmptyCommand *ecommand;
        KeyCommand *kcommand;
        KeyValCommand *kvcommand;
        KeyListCommand *klcommand;
    };
} Command;

/* List of commands, used to handle bulk requests, a stream of sequential
   commands to be executed in a single TCP request. */
typedef struct {
    size_t ncommands;
    Command **commands;
} BulkCommand;

/* A complete request, can be either a single command or a bulk one */
typedef struct {
    uint8_t reqtype;
    union {
        Command *command;
        BulkCommand *bulk_command;
    };
} Request;

/* Unpack a request from network byteorder (a big-endian) bytestream into a
   Request struct */
Request *unpack_request(Buffer *);

/* Unpack a command from network byteorder to a Command struct */
Command *unpack_command(Buffer *, Header *);

/* Cleanup functions */
void free_request(Request *, uint8_t);

void free_command(Command *);


// Response structure without body, like ACK etc.
typedef struct {
    Header *header;
    uint8_t code;
} NoContent;

// Response with data, like GET etc.
typedef struct {
    Header *header;
    uint32_t datalen;
    uint8_t *data;
} DataContent;

// Response with values, like COUNT etc.
typedef struct {
    Header *header;
    uint32_t val;
} ValueContent;

// Response with list, like glob GET etc.
typedef struct {
    Header *header;
    uint16_t len;
    struct Key **keys;
} ListContent;


typedef union {
    NoContent *ncontent;
    DataContent *dcontent;
    ValueContent *vcontent;
    ListContent *lcontent;
} Response;


Response *make_nocontent_response(uint8_t);
Response *make_datacontent_response(uint8_t *);
Response *make_valuecontent_response(uint32_t);
Response *make_listcontent_response(List *);

void pack_response(Buffer *, Response *, int);
void free_response(Response *, int);


#endif
