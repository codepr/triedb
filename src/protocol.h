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
#include "pack.h"
#include "vector.h"

/* Error codes */
#define OK                      0x00
#define NOK                     0x01
#define EOOM                    0x01


#define HEADER_LEN 2
#define ACK_LEN    2

/*
 * Command opcode, each TrieDB command is identified by the 7-4 bits of every
 * header which can be summarized by the following table:
 *
 *
 * OPCODE |    BIN    | HEX
 * -------|-----------|------
 *  PUT   | 00010000  | 0x10
 *  GET   | 00100000  | 0x20
 *  DEL   | 00110000  | 0x30
 *  TTL   | 01000000  | 0x40
 *  INC   | 01010000  | 0x50
 *  DEC   | 01100000  | 0x60
 *  CNT   | 01110000  | 0x70
 *  USE   | 10000000  | 0x80
 *  KEYS  | 10010000  | 0x90
 *  PING  | 10100000  | 0xa0
 *  QUIT  | 10110000  | 0xb0
 *  DB    | 11000000  | 0xc0
 *
 *  Header byte can be manipulated at bit level to toggle bit flags:
 *  e.g
 *
 *  PUT with PREFIX = 1  00010000 | (00010000 >> 1)  -> 00011000 -> 0x24
 */
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
    QUIT = 11,
    DB   = 12
};

/*
 * Definition of the common header, for now it simply define the operation
 * code, the total size of the packet including the body and uses a bitflag to
 * describe if it carries a prefix command or a single one.
 *
 * | Bit    | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
 * |--------|---------------|---------------|
 * | Byte 1 |     opcode    | p | reserved  |
 * |--------|-------------------------------|
 * | Byte 2 |                               |
 * |  .     |      Remaning Length          |
 * |  .     |                               |
 * | Byte 5 |                               |
 *
 * It's model loosely follow the MQTT fixed header format.
 * Reserved bits will be used for additional fueatures or cluster management.
 */

union header {

    unsigned char byte;

    struct {
        unsigned reserved : 3;
        unsigned prefix : 1;
        unsigned opcode : 4;
    } bits;
};


/********************************************/
/*             REQUEST STRUCTS              */
/********************************************/


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

typedef struct get use;

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

typedef struct ack db;


/*
 * Definition of a request, a union which encloses all possible command
 * requests.
 */
union triedb_request {

    union header header;

    struct ack ack;
    struct put put;
    struct get get;
    struct ttl ttl;

    inc incr;
    cnt count;
    use usec;
    db  get_db;

};


/********************************************/
/*             RESPONSE STRUCTS             */
/********************************************/


struct tuple {
    int ttl;
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

    union {

        struct {
            unsigned short tuples_len;
            struct tuple *tuples;
        };

        struct tuple val;
    };
};


struct cnt_response {

    union header header;

    unsigned long long val;
};


/*
 * Definition of a response, a union which encloses all possible command
 * response.
 */
union triedb_response {

    struct ack_response ack_res;
    struct get_response get_res;
    struct cnt_response cnt_res;
};


int encode_length(unsigned char *, size_t);

size_t decode_length(const unsigned char **, unsigned *);

/*
 * Unpack a response from network byteorder (a big-endian) bytestream into a
 * response struct
 */
int unpack_triedb_request(const unsigned char *,
                          union triedb_request *, unsigned char, size_t);

unsigned char *pack_triedb_request(const union triedb_request *, unsigned);

void triedb_request_destroy(union triedb_request *);

struct ack_response *ack_response(unsigned char , unsigned char);

struct get_response *get_response(unsigned char, const void *);

struct cnt_response *cnt_response(unsigned char, unsigned long long);

/*
 * Pack a response transforming all fields into their binary representation,
 * ready to be sent out in network byteorder
 */
unsigned char *pack_response(const union triedb_response *, unsigned);

/* Helper function to create a bytearray with a ACK code */
bstring pack_ack(unsigned char, unsigned char);

/* Helper function to create a bytearray with a CNT value */
bstring pack_cnt(unsigned char, unsigned long long);


#endif
