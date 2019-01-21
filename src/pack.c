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

#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <arpa/inet.h>
#include "pack.h"
#include "util.h"


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
struct buffer *buffer_create(size_t len) {

    struct buffer *b = tmalloc(sizeof(struct buffer));

    b->data = tmalloc(len);

    if (!b || !b->data)
        oom("allocating memory for new buffer");

    b->size = len;
    b->pos = 0;

    return b;
}


/* Destroy a previously allocated struct buffer structure */
void buffer_release(struct buffer *b) {

    if (!b)
        return;

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


int pack(struct buffer *buffer, const char *fmt, ...) {

    va_list ap;

    /* Byte, unsigned integer 8 bit */
    uint8_t B;

    /* Unsigned integer 16 bit */
    uint16_t H;

    /* Unsigned integer 32 bit */
    uint32_t I;

    /* Unsigned integer 64 bit */
    uint64_t Q;

    /* Bytestring */
    uint8_t *s;

    va_start(ap, fmt);

    for(; *fmt != '\0'; fmt++) {
        switch(*fmt) {

            case 'B': // 8-bit unsigned
                B = (uint8_t) va_arg(ap, uint32_t);
                write_uint8(buffer, B);
                break;

            case 'H': // 16-bit unsigned
                H = (uint16_t) va_arg(ap, uint32_t);
                write_uint16(buffer, H);
                break;

            case 'I': // 32-bit unsigned
                I = va_arg(ap, uint32_t);
                write_uint32(buffer, I);
                break;

            case 'Q': // 64-bit unsigned
                Q = va_arg(ap, uint64_t);
                write_uint64(buffer, Q);
                break;

            case 's': // bytestring
                s = va_arg(ap, uint8_t *);
                write_bytes(buffer, s);
                break;
        }
    }

    va_end(ap);

    return buffer->size;
}


void unpack(struct buffer *buffer, const char *fmt, ...) {

    va_list ap;

    /* Byte, unsigned integer 8 bit */
    uint8_t *B;

    /* Unsigned integer 16 bit */
    uint16_t *H;

    /* Unsigned integer 32 bit */
    uint32_t *I;

    /* Unsigned integer 64 bit */
    uint64_t *Q;

    /* Bytestring */
    uint8_t *s;

    size_t len = 0;

    va_start(ap, fmt);

    for (; *fmt != '\0'; fmt++) {

        switch (*fmt) {

            case 'B': // 8-bit unsigned
                B = va_arg(ap, uint8_t *);
                *B = read_uint8(buffer);
                break;

            case 'H': // 16-bit unsigned
                H = va_arg(ap, uint16_t *);
                *H = read_uint16(buffer);
                break;

            case 'I': // 32-bit unsigned
                I = va_arg(ap, uint32_t *);
                *I = read_uint32(buffer);
                break;

            case 'Q': // 64-bit unsigned
                Q = va_arg(ap, uint64_t *);
                *Q = read_uint64(buffer);
                break;

            case 's': // bytestring
                s = va_arg(ap, uint8_t *);
                uint8_t *buf = read_bytes(buffer, len);
                memcpy(s, buf, len);
                tfree(buf);
                s[len] = 0;
                len = 0;
                break;

            default:
                if (isdigit(*fmt))
                    len = len * 10 + (*fmt - '0');
        }
    }

    va_end(ap);
}
