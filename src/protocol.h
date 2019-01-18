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

/* struct request type */
#define SINGLE_REQUEST          0x00
#define BULK_REQUEST            0x01

/* Header flags */
#define F_NOFLAG                1 << 0
#define F_BULKREQUEST           1 << 1
#define F_PREFIXREQUEST         1 << 2
#define F_FROMNODEREQUEST       1 << 3
#define F_FROMNODERESPONSE      1 << 4

/* Command type */
#define EMPTY_COMMAND           0x00
#define KEY_COMMAND             0x01
#define KEY_VAL_COMMAND         0x02
#define KEY_LIST_COMMAND        0x03
#define KEY_VAL_LIST_COMMAND    0x04

/* union response type */
#define NO_CONTENT              0x00
#define DATA_CONTENT            0x01
#define VALUE_CONTENT           0x02
#define LIST_CONTENT            0x03

#define COMMAND_COUNT           14

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
#define USE                     0x09
#define CLUSTER_JOIN            0x0a
#define PING                    0xfc
#define DB                      0xfd
#define INFO                    0xfe
#define QUIT                    0xff


/*
 * 8 bytes to store the operation code (PUT, GET etc ...) the total length of
 * the packet and if it is a single command or a stream of sequential commands,
 * a prefix command and the source of the request (being it from a client or
 * from another node)
 *
 * [ 1 byte ] | [ 4 bytes ] | [ 1 byte ] | [ 1 byte ] | [1 byte ] | [ 1 byte ]
 * ---------- | ----------- | ---------- | ---------- | --------- | ----------
 *  opcode    | packet len  | bulk flag  | prefix flag| source req| source res
 * ---------- | ----------- | ---------- | ---------- | --------- | ----------
 *
 */
#define HEADERLEN (5 * sizeof(uint8_t)) + sizeof(uint32_t)


/* struct buffer structure, provides a convenient way of handling byte string data.
   It is essentially an unsigned char pointer that track the position of the
   last written byte and the total size of the bystestring */
struct buffer {
    size_t size;
    size_t pos;
    uint8_t *data;
};

/* Host to network byteorder for unsigned long long values, it is achieved by
   treating a single u64 as two u32 numbers */
void htonll(uint8_t *, uint_least64_t);

/* Network to host byteorder for unsigned long long values, it is achieved by
   treating a single u64 as two u32 numbers */
uint_least64_t ntohll(const uint8_t *);

/*
 * struct buffer constructor, it require a size cause we use a bounded buffer,
 * e.g. no resize over a defined size
 */
struct buffer *buffer_init(size_t);

void buffer_destroy(struct buffer *);


/* Reading data on struct buffer pointer */
// bytes -> uint8_t
uint8_t read_uint8(struct buffer *);
// bytes -> uint16_t
uint16_t read_uint16(struct buffer *);
// bytes -> uint32_t
uint32_t read_uint32(struct buffer *);
// bytes -> uint64_t
uint64_t read_uint64(struct buffer *);
// read a defined len of bytes
uint8_t *read_bytes(struct buffer *, size_t);


/* Write data on struct buffer pointer */
// append a uint8_t -> bytes into the buffer
void write_uint8(struct buffer *, uint8_t);
// append a uint16_t -> bytes into the buffer
void write_uint16(struct buffer *, uint16_t);
// append a uint32_t -> bytes into the buffer
void write_uint32(struct buffer *, uint32_t);
// append a uint64_t -> bytes into the buffer
void write_uint64(struct buffer *, uint64_t);
// append len bytes into the buffer
void write_bytes(struct buffer *, uint8_t *);


/*
 * Definition of the common header, for now it simply define the operation
 * code, the total size of the packet including the body and uses a bitflag to
 * describe if it carries a single command or a stream of sequential commands,
 * a prefix or a normal command and the source of the request or response,
 * which can be either a normal client or another tritedb node.
 *
 * In the second case, when another node send a request it communicates also a
 * transaction ID, which will be used to send a response to the requesting
 * client.
 */
struct header {
    uint8_t opcode;
    uint8_t flags;
    uint32_t size;
    char transaction_id[37];
};

/*
 * Definition of a single key, with `is_prefix` defining if the key must be
 * treated as a prefix, in other words if the command which operates on it
 * have to be used as a glob style command e.g. DEL hello* deletes all keys
 * starting with hello
 * TODO: remove is_prefix
 */
struct key {
    uint16_t keysize;
    uint8_t *key;
    uint8_t is_prefix;
};

/*
 * Definition of a key-value pair, for the rest it is equal to Key
 * TODO: remove is_prefix
 */
struct keyval {
    uint16_t keysize;
    uint32_t valsize;
    uint8_t *key;
    uint8_t *val;
    uint8_t is_prefix;
};

/*
 * Empty command, for those commands that doesn't require a body at all, like
 * QUIT
 */
struct empty_command {
    struct header *header;
};

/*
 * For all commands that does only need key field and some extra optionals
 * fields like the time to live (`ttl`) or the `is_prefix` flag
 * e.g. GET, TTL, INC, DEC.. etc
 * TODO: remove is_prefix
 */
struct key_command {
    struct header *header;
    uint16_t keysize;
    uint8_t *key;
    uint8_t is_prefix;
    uint16_t ttl;
};

/*
 * For all commands that does need key and val fields with some extra optionals
 * fields like the time to live (`ttl`) or the `is_prefix` flag e.g. PUT .. etc
 * TODO: remove is_prefix
 */
struct keyval_command {
    struct header *header;
    uint16_t keysize;
    uint32_t valsize;
    uint8_t *key;
    uint8_t *val;
    uint8_t is_prefix;
    uint16_t ttl;
};

/*
 * For all commands that does need a list of keys with some extra optionals
 * fields like the time to live (`ttl`) or the `is_prefix` flag e.g. DEL .. etc
 */
struct key_list_command {
    struct header *header;
    uint32_t len;
    struct key **keys;
};

// For commands list formed by key-value complete pairs
struct keyval_list_command {
    struct header *header;
    uint16_t len;
    struct keyvalue **pairs;
};

/*
 * Define a request, can be either an `struct empty_command`, a `struct key_command`, a
 * `struct keyval_command` or a `struct key_list_command`
 * TODO move header outside of each single command
 */
struct command {
    uint8_t cmdtype;
    union {
        struct empty_command *ecommand;
        struct key_command *kcommand;
        struct keyval_command *kvcommand;
        struct key_list_command *klcommand;
    };
};

/* List of commands, used to handle bulk requests, a stream of sequential
   commands to be executed in a single TCP request. */
struct bulk_command {
    uint32_t ncommands;
    struct command **commands;
};

/* A complete request, can be either a single command or a bulk one */
struct request {
    uint8_t reqtype;
    union {
        struct command *command;
        struct bulk_command *bulk_command;
    };
};

/* Unpack a request from network byteorder (a big-endian) bytestream into a
   struct request struct */
struct request *unpack_request(struct buffer *);

/* Unpack a command from network byteorder to a Command struct */
struct command *unpack_command(struct buffer *, struct header *);

/* Cleanup functions */
void free_request(struct request *, uint8_t);

void free_command(struct command *, bool);


// union response structure without body, like ACK etc.
struct no_content {
    struct header *header;
    uint8_t code;
};

// union response with data, like GET etc.
struct data_content {
    struct header *header;
    uint32_t datalen;
    uint8_t *data;
};

// union response with values, like COUNT etc.
struct value_content {
    struct header *header;
    uint32_t val;
};

// union response with list, like glob GET etc.
struct list_content {
    struct header *header;
    uint16_t len;
    struct key **keys;
};


union response {
    struct no_content *ncontent;
    struct data_content *dcontent;
    struct value_content *vcontent;
    struct list_content *lcontent;
};

/*
 * Response builder functions, accept a payload as first argument and header
 * flags as third, passed in in order of activation by using | operator.
 *
 * Second argument is a transaction_id in case of F_FROMNODERESPONSE flag on.
 */
union response *make_ack_response(uint8_t, const uint8_t *, uint8_t);
union response *make_data_response(const uint8_t *, const uint8_t *, uint8_t);
union response *make_valuecontent_response(uint32_t, const uint8_t *, uint8_t);
union response *make_list_response(const List *, const uint8_t *, uint8_t);

/* Request builder functions, essentially mirroring of response builders */
struct request *make_key_request(const uint8_t *,
        uint8_t, uint8_t, uint16_t, uint8_t);

// Response -> byte buffer
void pack_response(struct buffer *, const union response *, int);

void free_response(union response *, int);

void pack_request(struct buffer *, const struct request *, int);


#endif
