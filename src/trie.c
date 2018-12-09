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

// C implementation of search and insert operations
// on Trie
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "trie.h"

/* Converts key current character into index starting from <space> till '~',
   96 characters in total, lowercase and uppercase letters included */
#define INDEX(c) ((int)c - (int)' ')


static bool trie_is_free_node(TrieNode *node) {
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (node->children[i])
            return false;
    }
    return true;
}


// Returns new trie node (initialized to NULL)
TrieNode *trie_new_node(void) {

	TrieNode *new_node = new_node = malloc(sizeof(*new_node));

	if (new_node) {
		int i;

		new_node->leaf = false;
        new_node->in_use = true;

		for (i = 0; i < ALPHABET_SIZE; i++)
			new_node->children[i] = NULL;
	}

	return new_node;
}

// Returns new Trie, with a NULL root and 0 size
Trie *trie_new(void) {
    Trie *trie = malloc(sizeof(*trie));
    trie->root = trie_new_node();
    trie->size = 0;
    return trie;
}

/* If not present, inserts key into trie, if the key is prefix of trie node,
   just marks leaf node.

   Being a Trie, it should guarantees O(m) performance for insertion on the
   worst case, where `m` is the length of the key. */
static int trie_node_insert(TrieNode *root, const char *key, void *data) {

    int retval = 0;
	int level;
	int length = strlen(key);
	int index;

	TrieNode *cursor = root;

	for (level = 0; level < length; level++) {
		index = INDEX(key[level]);
		if (!cursor->children[index])
			cursor->children[index] = trie_new_node();

		cursor = cursor->children[index];
	}

    if (cursor->in_use == true) {
        retval = 1;
    } else {
        cursor->in_use = true;
    }

	// mark last node as leaf
	cursor->leaf = true;
    cursor->data = data;

    return retval;
}


static bool trie_node_recursive_delete(TrieNode *node, const char *key, int level, int len) {
    if (node) {
        // Base case
        if (level == len) {
            if (node->leaf) {
                // Unmark leaf node
                node->leaf = false;
                node->in_use = false;

                // If empty, node to be deleted
                return trie_is_free_node(node);
            }
        } else {
            int index = INDEX(key[level]);

            if (trie_node_recursive_delete(node->children[index], key, level + 1, len)) {
                // last node marked, delete it
                free(node->children[index]);
                node->children[index] = NULL;

                // recursively climb up, and delete eligible nodes
                return (!node->leaf && trie_is_free_node(node));
            }
        }
    }

    return false;
}


/* Returns true if key presents in trie, else false. Also for lookup the big-O
   runtime is guaranteed O(m) with `m` as length of the key. */
static bool trie_node_search(TrieNode *root, const char *key, void **ret) {
	int level;
	int length = strlen(key);
	int index;

	TrieNode *cursor = root;

	for (level = 0; level < length; level++) {
		index = INDEX(key[level]);

		if (!cursor->children[index]) {
            *ret = NULL;
			return false;
        }

		cursor = cursor->children[index];
	}

    if (cursor && cursor->leaf) {
        *ret = cursor->data;
        return true;
    }
	return false;
}


void trie_insert(Trie *trie, const char *key, void *data) {
    assert(trie);
    assert(key);
    if (trie_node_insert(trie->root, key, data) == 1)
        trie->size++;
}


void trie_delete(Trie *trie, const char *key) {
    assert(trie);
    assert(key);
    int len = strlen(key);
    if (len > 0) {
        trie_node_recursive_delete(trie->root, key, 0, len);
        trie->size--;
    }
}


bool trie_search(Trie *trie, const char *key, void **ret) {
    assert(trie);
    assert(key);
    return trie_node_search(trie->root, key, ret);
}


static void trie_node_free(TrieNode *node) {
    if (node) {

        if (node->leaf && node->data) {
            node->leaf = false;
            free(node->data);
        }

        for (int i = 0; i < ALPHABET_SIZE; i++)
            trie_node_free(node->children[i]);

        free(node);
    }
}


void trie_free(Trie *trie) {
    if (!trie)
        return;
    trie_node_free(trie->root);
    free(trie);
}
