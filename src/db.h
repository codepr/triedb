/* BSD 2-Clause License
 *
 * Copyright (c) 2018, 2019, Andrea Giacomo Baldan All rights reserved.
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

#ifndef DB_H
#define DB_H

#include <time.h>
#include "trie.h"


struct db_item {
    short ttl;
    void *data;
    time_t ctime;
    time_t lstime;
};

/*
 * Simple database abstraction, provide some namespacing to keyspace for each
 * client
 */
struct database {
    const char *name;
    Trie *data;
};


void database_init(struct database *, const char *,
                   int (*destructor)(struct trie_node *));

size_t database_size(const struct database *);

/*
 * Insert a new key-value pair in the Trie structure, returning a pointer to
 * the new inserted data in order to simplify some operations as the addition
 * of expiring keys with a set TTL.
 */
void database_insert(struct database *, const char *, const void *, short);

/*
 * Returns true if key is present in trie, else false. Also for lookup the
 * big-O runtime is guaranteed O(m) with `m` as length of the key.
 */
bool database_search(const struct database *, const char *, void **);

bool database_remove(struct database *, const char *);

/*
 * Remove and delete all keys matching a given prefix in the trie
 * e.g. hello*
 * - hello
 * hellot
 * helloworld
 * hello
 */
void database_prefix_remove(struct database *, const char *);

/* Count all keys matching a given prefix in a less than linear time
   complexity */
int database_prefix_count(const struct database *, const char *);

/* Search for all keys matching a given prefix */
Vector *database_prefix_search(const struct database *, const char *);

/*
 * Set value to all keys matching a given prefix in a less than linear time
 * complexity
 */
void database_prefix_set(struct database *, const char *, const void *, short);

/*
 * Integer modifying function. Check if a subset of the trie matching a given
 * prefix contains integer and increment it by a value
 */
void database_prefix_inc(struct database *, const char *);

/*
 * Integer modifying function. Check if a subset of the trie matching a given
 * prefix contains integer and decrement it by a value
 */
void database_prefix_dec(struct database *, const char *);

/*
 * Set TTL to all keys matching a given prefix in a less than linear time
 * complexity
 */
void database_prefix_ttl(struct database *, const char *, short);


#endif
