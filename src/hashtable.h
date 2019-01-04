/*
 * BSD 2-Clause License
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

#ifndef HASHTABLE_H
#define HASHTABLE_H


#include <stdint.h>
#include <stdbool.h>


#define HASHTABLE_OK   0
#define HASHTABLE_ERR  1
#define HASHTABLE_OOM  2
#define HASHTABLE_FULL 3

#define CRC32(c, x) crc32(c, x)


/* We need to keep keys and values */
typedef struct {
    const void *key;
    void *val;
    bool taken;
} HashTableEntry;


/*
 * An HashTable has some maximum size and current size, as well as the data to
 * hold.
 */
typedef struct {
    uint64_t table_size;
    uint64_t size;
    HashTableEntry *entries;
} HashTable;


/* HashTable API */
HashTable *hashtable_create(void);

void hashtable_release(HashTable *);

int hashtable_put(HashTable *, const void *, void *);

void *hashtable_get(HashTable *, const void *);

int hashtable_del(HashTable *, const void *);

int hashtable_iterate(HashTable *, int (*func)(void *));

void hashtable_custom_release(HashTable *, int (*func)(void *));

uint64_t crc32(const uint8_t *, const uint32_t);

#endif
