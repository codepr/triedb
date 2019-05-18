/* BSD 2-Clause License
 *
 * Copyright (c) 2018, 2019 Andrea Giacomo Baldan
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
// #include <stdint.h>
// #include "list.h"
// #include "util.h"
#include "pack.h"

/* Error codes */
#define OK                      0x00
#define NOK                     0x01
#define EOOM                    0x01

/* struct request type */
// #define SINGLE_REQUEST          0x00
// #define BULK_REQUEST            0x01
//
// /* Header flags */
// #define F_NOFLAG                1 << 0
// #define F_BULKREQUEST           1 << 1
// #define F_PREFIXREQUEST         1 << 2
// #define F_FROMNODEREQUEST       1 << 3
// #define F_FROMNODERESPONSE      1 << 4
// #define F_JOINREQUEST           1 << 5
// #define F_FROMNODEREPLY         1 << 6
//
// /* Command type */
// #define EMPTY_COMMAND           0x00
// #define KEY_COMMAND             0x01
// #define KEY_VAL_COMMAND         0x02
// #define KEY_LIST_COMMAND        0x03
// #define KEY_VAL_LIST_COMMAND    0x04
//
// /* struct response type */
// #define NO_CONTENT              0x00
// #define DATA_CONTENT            0x01
// #define VALUE_CONTENT           0x02
// #define LIST_CONTENT            0x03
// #define KVLIST_CONTENT          0x04
//
// #define COMMAND_COUNT           16
//
// /* Operation codes */
// #define ACK                     0x00
// #define PUT                     0x01
// #define GET                     0x02
// #define DEL                     0x03
// #define TTL                     0x04
// #define INC                     0x05
// #define DEC                     0x06
// #define COUNT                   0x07
// #define KEYS                    0x08
// #define USE                     0x09
// #define CLUSTER_JOIN            0x0a
// #define CLUSTER_MEMBERS         0x0b
// #define PING                    0xfc
// #define DB                      0xfd
// #define INFO                    0xfe
// #define QUIT                    0xff


#define HEADER_LEN 2
#define ACK_LEN    2

/* Message types */
enum opcode {
    ACK  = 0,
    PUT  = 1,
    GET  = 2,
    DEL  = 3,
    TTL  = 4,
    INC  = 5,
    DEC  = 6,
    CNT  = 7,
    USE  = 8,
    KEYS = 9,
    PING = 10,
    QUIT = 11
};


union header {

    unsigned char byte;

    struct {
        unsigned reserved : 3;
        unsigned prefix : 1;
        unsigned opcode : 4;
    } bits;
};


struct put {

    union header header;

    int ttl;
    unsigned short keylen;
    unsigned char *key;
    unsigned char *val;
};


struct get {

    union header header;

    unsigned char *key;
};


typedef struct get del;

typedef struct get inc;

typedef struct get dec;

typedef struct get cnt;

typedef struct get keys;


struct ttl {

    union header header;

    int ttl;
    unsigned char *key;
};


struct ack {

    union header header;

    unsigned char rc;
};


typedef struct ack ping;

typedef struct ack quit;


union triedb_request {

    union header header;

    struct ack ack;
    struct put put;
    struct get get;
    struct ttl ttl;

    inc incr;
    cnt count;

};


/* RESPONSE */


struct tuple {
    unsigned ttl;
    unsigned short keylen;
    unsigned char *key;
    unsigned char *val;
};


struct ack_response {

    union header header;

    unsigned char rc;
};


struct get_response {

    union header header;

    unsigned short tuples_len;

    struct tuple *tuples;
};


struct cnt_response {

    union header header;

    unsigned long long val;
};


union triedb_response {

    struct ack_response ack_res;
    struct get_response get_res;
    struct cnt_response cnt_res;
};


int encode_length(unsigned char *, size_t);

size_t decode_length(const unsigned char **, unsigned *);

int unpack_triedb_request(const unsigned char *,
                          union triedb_request *, unsigned char, size_t);

unsigned char *pack_triedb_request(const union triedb_request *, unsigned);

void triedb_request_destroy(union triedb_request *);

struct ack_response *ack_response(unsigned char , unsigned char);

struct get_response *get_response(unsigned char, unsigned short, struct tuple *);

struct cnt_response *cnt_response(unsigned char, unsigned long long);

void pack_response(unsigned char *, const union triedb_response *, unsigned);

bstring pack_ack(unsigned char, unsigned);

bstring pack_cnt(unsigned char, unsigned long long);


/*
 * 6 bytes to store the operation code (PUT, GET etc ...) the total length of
 * the packet and if it is a single command or a stream of sequential commands,
 * a prefix command and the source of the request (being it from a client or
 * from another node).
 * In case of packet incoming from another node it optionally store a
 * transaction id of 36 bytes length, a UUID representing univocally the
 * operation in progress.
 *
 * [ 1 byte ] | [ 4 bytes ] | [ 1 byte ] | [ 36 bytes (opt) ]
 * ---------- | ----------- | ---------- | ------------------
 *   opcode   | packet len  |   flags    |   transaction id
 * ---------- | ----------- | ---------- | ------------------
 *
 */
// #define HEADERLEN (2 * sizeof(uint8_t)) + sizeof(uint32_t)


/*
 * Definition of the common header, for now it simply define the operation
 * code, the total size of the packet including the body and uses a bitflag to
 * describe if it carries a single command or a stream of sequential commands,
 * a prefix or a normal command and the source of the request or response,
 * which can be either a normal client or another triedb node.
 *
 * In the second case, when another node send a request it communicates also a
 * transaction ID, which will be used to send a response to the requesting
 * client.
 */
// struct header {
//     uint8_t opcode;
//     uint8_t flags;
//     uint32_t size;
//     char transaction_id[UUID_LEN];
// };
//
//
// /********************************************
//  *             REQUEST STRUCTS
//  ********************************************/
//
//
// /*
//  * Definition of a single key, with `is_prefix` defining if the key must be
//  * treated as a prefix, in other words if the command which operates on it
//  * have to be used as a glob style command e.g. DEL hello* deletes all keys
//  * starting with hello
//  * TODO: remove is_prefix
//  */
// struct key {
//     uint16_t keysize;
//     uint8_t *key;
//     uint8_t is_prefix;
// };
//
// /*
//  * Definition of a key-value pair, for the rest it is equal to Key
//  * TODO: remove is_prefix
//  */
// struct keyval {
//     uint16_t keysize;
//     uint32_t valsize;
//     uint8_t *key;
//     uint8_t *val;
//     uint8_t is_prefix;
// };
//
// /*
//  * Empty command, for those commands that doesn't require a body at all, like
//  * QUIT
//  */
// struct empty_command {
//     struct header *header;
// };
//
// /*
//  * For all commands that does only need key field and some extra optionals
//  * fields like the time to live (`ttl`) or the `is_prefix` flag
//  * e.g. GET, TTL, INC, DEC.. etc
//  * TODO: remove is_prefix
//  */
// struct key_command {
//     struct header *header;
//     uint16_t keysize;
//     uint8_t *key;
//     uint8_t is_prefix;
//     uint16_t ttl;
// };
//
// /*
//  * For all commands that does need key and val fields with some extra optionals
//  * fields like the time to live (`ttl`) or the `is_prefix` flag e.g. PUT .. etc
//  * TODO: remove is_prefix
//  */
// struct keyval_command {
//     struct header *header;
//     uint16_t keysize;
//     uint32_t valsize;
//     uint8_t *key;
//     uint8_t *val;
//     uint8_t is_prefix;
//     uint16_t ttl;
// };
//
// /*
//  * For all commands that does need a list of keys with some extra optionals
//  * fields like the time to live (`ttl`) or the `is_prefix` flag e.g. DEL .. etc
//  */
// struct key_list_command {
//     struct header *header;
//     uint32_t len;
//     struct key **keys;
// };
//
// // For commands list formed by key-value complete pairs
// struct keyval_list_command {
//     struct header *header;
//     uint16_t len;
//     struct keyvalue **pairs;
// };
//
// /*
//  * Define a request, can be either an `struct empty_command`, a `struct key_command`, a
//  * `struct keyval_command` or a `struct key_list_command`
//  * TODO move header outside of each single command
//  */
// struct command {
//     uint8_t cmdtype;
//     union {
//         struct empty_command *ecommand;
//         struct key_command *kcommand;
//         struct keyval_command *kvcommand;
//         struct key_list_command *klcommand;
//     };
// };
//
// /*
//  * List of commands, used to handle bulk requests, a stream of sequential
//  * commands to be executed in a single TCP request.
//  */
// struct bulk_command {
//     uint32_t ncommands;
//     struct command **commands;
// };
//
// /* A complete request, can be either a single command or a bulk one */
// struct request {
//     uint8_t reqtype;
//     union {
//         struct command *command;
//         struct bulk_command *bulk_command;
//     };
// };
//
// /*
//  * Pack a request transforming all fields into their binary representation,
//  * ready to be sent out in network byteorder
//  */
// void pack_request(struct buffer *, const struct request *, int);
//
// /*
//  * Unpack a request from network byteorder (a big-endian) bytestream into a
//  * request struct
//  */
// struct request *unpack_request(struct buffer *);
//
// /* Request builder functions, essentially mirroring of response builders */
// struct request *make_key_request(const uint8_t *, uint8_t, uint16_t, uint8_t);
// struct request *make_keyval_request(const uint8_t *,
//         const uint8_t *, uint8_t, uint16_t, uint8_t);
// struct request *make_keylist_request(const List *,
//         uint8_t, const uint8_t *, uint8_t);
//
// /* Cleanup functions */
// void free_request(struct request *);
//
//
// /********************************************
//  *             RESPONSE STRUCTS
//  ********************************************/
//
//
// // struct response structure without body, like ACK etc.
// struct no_content {
//     struct header *header;
//     uint8_t code;
// };
//
// // struct response with data, like GET etc.
// struct data_content {
//     struct header *header;
//     uint32_t datalen;
//     uint8_t *data;
// };
//
// // struct response with values, like COUNT etc.
// struct value_content {
//     struct header *header;
//     uint32_t val;
// };
//
// // struct response with list, like glob GET etc.
// struct list_content {
//     struct header *header;
//     uint16_t len;
//     struct key **keys;
// };
//
// // Response with key-val pairs list
// struct kvlist_content {
//     struct header *header;
//     uint16_t len;
//     struct keyval **pairs;
// };
//
//
// struct response {
//     uint8_t restype;
//     union {
//         struct no_content *ncontent;
//         struct data_content *dcontent;
//         struct value_content *vcontent;
//         struct list_content *lcontent;
//         struct kvlist_content *kvlcontent;
//     };
// };
//
// /*
//  * Response builder functions, accept a payload as first argument and header
//  * flags as third, passed in in order of activation by using | operator.
//  *
//  * Second argument is a transaction_id in case of F_FROMNODERESPONSE flag on.
//  */
// struct response *make_ack_response(uint8_t, const uint8_t *, uint8_t);
// struct response *make_data_response(const uint8_t *, const uint8_t *, uint8_t);
// struct response *make_valuecontent_response(uint32_t, const uint8_t *, uint8_t);
// struct response *make_list_response(const List *, const uint8_t *, uint8_t);
// struct response *make_kvlist_response(const List *, const uint8_t *, uint8_t);
//
//
// void ack_response_init(struct response *, uint8_t, int, const char *);
// void data_response_init(struct response *,
//         const uint8_t *, uint8_t, const char *);
// void value_response_init(struct response *, uint32_t, uint8_t, const char *);
//
// /*
//  * Pack a response transforming all fields into their binary representation,
//  * ready to be sent out in network byteorder
//  */
// void pack_response(struct buffer *, const struct response *);
//
// /*
//  * Unpack a response from network byteorder (a big-endian) bytestream into a
//  * response struct
//  */
// struct response *unpack_response(struct buffer *);
//
// void free_response(struct response *);


#endif
