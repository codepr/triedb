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

#ifndef PACK_H
#define PACK_H

#include <stdint.h>


/*
 * Buffer structure, provides a convenient way of handling byte string data.
 * It is essentially an unsigned char pointer that track the position of the
 * last written byte and the total size of the bystestring
 */
struct buffer {
    size_t size;
    size_t pos;
    uint8_t *data;
};

/*
 * Host to network byteorder for unsigned long long values, it is achieved by
 * treating a single u64 as two u32 numbers
 */
void htonll(uint8_t *, uint_least64_t);

/* Network to host byteorder for unsigned long long values, it is achieved by
   treating a single u64 as two u32 numbers */
uint_least64_t ntohll(const uint8_t *);

/*
 * struct buffer constructor, it require a size cause we use a bounded buffer,
 * e.g. no resize over a defined size
 */
struct buffer *buffer_create(size_t);

void buffer_release(struct buffer *);


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


int pack(struct buffer *, const char *, ...);

void unpack(struct buffer *, const char *, ...);


#endif
