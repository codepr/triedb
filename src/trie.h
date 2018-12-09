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

#include <stdio.h>
#include <stdbool.h>


#define ALPHABET_SIZE (94)


typedef struct Trie Trie;

typedef struct TrieNode TrieNode;


/* Trie node, it contains a fixed size array (every node can have at max the
   alphabet length size of children), a flag defining if the node represent
   the end of a word and then if it contains a value defined by data. */
struct TrieNode {
	struct TrieNode *children[ALPHABET_SIZE];
    void *data;
	/* leaf is true if the node represents end of a word */
	bool leaf;
    bool in_use;
};


/* Trie ADT, it is formed by a root TrieNode, and the total size of the Trie */
struct Trie {
    struct TrieNode *root;
    size_t size;
};


// Returns new trie node (initialized to NULLs)
struct TrieNode *trie_new_node();

struct Trie *trie_new(void);

/* The leaf represents the node with the associated data */
void trie_insert(Trie *, const char *, void *);

void trie_delete(Trie *, const char *);

/* Returns true if key presents in trie, else false, the last pointer to
   pointer is used to store the value associated with the searched key, if
   present */
bool trie_search(Trie *, const char *, void **);

void trie_free(Trie *);


#endif
