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

#ifndef TRIE_H
#define TRIE_H

#include <time.h>
#include <stdbool.h>
#include "list.h"


#define NOTTL           1


typedef struct Trie Trie;

/* Main data structure, contains the data to be stored on leaf nodes */
struct node_data {
    time_t ctime;  // creation time
    time_t latime; // last access time
    int16_t ttl;   // time to live
    void *data;    // payload
};

/*
 * Trie node, it contains a fixed size array (every node can have at max the
 * alphabet length size of children), a flag defining if the node represent
 * the end of a word and then if it contains a value defined by data.
 */
struct trie_node {
    char chr;
    List *children;
    struct node_data *ndata;
};


/*
 * Trie ADT, it is formed by a root struct trie_node, and the total size of the
 * Trie
 */
struct Trie {
    struct trie_node *root;
    size_t size;
};

// Returns new trie node (initialized to NULLs)
struct trie_node *trie_new_node(char);

// Returns a new Trie, which is formed by a root node and a size
struct Trie *trie_new(void);

// Return the size of the trie
size_t trie_size(const Trie *);

/*
 * The leaf represents the node with the associated data
 *           .
 *          / \
 *         h   s: s-value
 *        / \
 *       e   k: hk-value
 *      /
 *     l: hel-value
 *
 * Here we got 3 <key:value> pairs:
 * - s: s-value
 * - hk: hk-value
 * - hel: hel-value
 */
struct node_data *trie_insert(Trie *, const char *, const void *);

bool trie_delete(Trie *, const char *);

/* Returns true if key presents in trie, else false, the last pointer to
   pointer is used to store the value associated with the searched key, if
   present */
bool trie_find(const Trie *, const char *, void **);

void trie_node_free(struct trie_node *, size_t *);

void trie_free(Trie *);

/* Remove all keys matching a given prefix in a less than linear time
   complexity */
void trie_prefix_delete(Trie *, const char *);

/* Count all keys matching a given prefix in a less than linear time
   complexity */
int trie_prefix_count(const Trie *, const char *);

/*
 * Integer modifying function. Check if a subset of the trie matching a given
 * prefix contains integer and increment it by a value
 */
void trie_prefix_inc(Trie *, const char *);

/*
 * Integer modifying function. Check if a subset of the trie matching a given
 * prefix contains integer and decrement it by a value
 */
void trie_prefix_dec(Trie *, const char *);

/* Set value to all keys matching a given prefix in a less than linear time
   complexity */
void trie_prefix_set(Trie *, const char *, const void *, int16_t);

/* Set TTL to all keys matching a given prefix in a less than linear time
   complexity */
void trie_prefix_ttl(Trie *, const char *, int16_t);

/* Search for all keys matching a given prefix */
List *trie_prefix_find(const Trie *, const char *);

/* Apply a given function to all nodes which keys match a given prefix */
void trie_prefix_map(Trie *, const char *, void (*mapfunc)(struct trie_node *));


#endif
