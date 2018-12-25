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
TrieNode *trie_new_node(void *data) {

    TrieNode *new_node = malloc(sizeof(*new_node));

    if (new_node) {

        struct NodeData *ndata = malloc(sizeof(*ndata));

        ndata->ttl = NOTTL;
        ndata->ctime = (uint64_t) time(NULL);
        ndata->data = data;

        new_node->leaf = false;
        new_node->in_use = true;
        new_node->ndata = ndata;

        for (int i = 0; i < ALPHABET_SIZE; i++)
            new_node->children[i] = NULL;
    }

    return new_node;
}

// Returns new Trie, with a NULL root and 0 size
Trie *trie_new(void) {
    Trie *trie = malloc(sizeof(*trie));
    trie->root = trie_new_node(NULL);
    trie->size = 0;
    return trie;
}

/* If not present, inserts key into trie, if the key is prefix of trie node,
   just marks leaf node.

   Being a Trie, it should guarantees O(m) performance for insertion on the
   worst case, where `m` is the length of the key. */
static int trie_node_insert(TrieNode *root, const char *key, void *data) {

    int retval = 0;
    int index;

    TrieNode *cursor = root;

    for (char x = *key; x != '\0'; x = *(++key)) {
        index = INDEX(x);
        if (!cursor->children[index])
            cursor->children[index] = trie_new_node(NULL);

        cursor = cursor->children[index];
    }

    if (cursor->in_use == true) {
        retval = 1;
    } else {
        cursor->in_use = true;
    }

    // mark last node as leaf
    cursor->leaf = true;
    cursor->ndata->data = data;

    return retval;
}

/* Private function, iterate recursively through the trie structure starting
   from a given node, deleting the target value */
static bool trie_node_recursive_delete(TrieNode *node, const char *key, size_t *size, bool *found) {

    if (node) {
        // Base case
        if (*key == '\0') {
            if (node->leaf) {
                // Unmark leaf node
                node->leaf = node->in_use = false;
                // Update trie size
                (*size)--;
                // Update found flag
                *found = true;

                // If empty, node to be deleted
                return trie_is_free_node(node);
            }
        } else {

            int index = INDEX(*key);

            if (trie_node_recursive_delete(node->children[index], key + 1, size, found)) {
                // last node marked, delete it
                trie_node_free(node->children[index]);
                node->children[index] = NULL;

                // recursively climb up, and delete eligible nodes
                return (!node->leaf && trie_is_free_node(node));
            }
        }
    }

    return false;
}

// XXX debugging only
// function to display the content of Trie
void display(TrieNode* root, char str[], int level) {
    // If node is leaf node, it indiicates end
    // of string, so a null charcter is added
    // and string is displayed
    if (root->leaf) {
        str[level] = '\0';
        printf("%s\n", str);
    }

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        // if NON NULL child is found
        // add parent key to str and
        // call the display function recursively
        // for child node
        if (root->children[i]) {
            str[level] = i + ' ';
            display(root->children[i], str, level + 1);
        }
    }
}

/* Returns true if key presents in trie, else false. Also for lookup the big-O
   runtime is guaranteed O(m) with `m` as length of the key. */
static bool trie_node_search(TrieNode *root, const char *key, void **ret) {

    int index;

    TrieNode *cursor = root;

    for (char c = *key; c != '\0'; c = *(++key)) {
        index = INDEX(c);

        if (!cursor->children[index]) {
            *ret = NULL;
            return false;
        }

        cursor = cursor->children[index];
    }

    if (cursor && cursor->leaf) {
        *ret = cursor->ndata;
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


bool trie_delete(Trie *trie, const char *key) {

    assert(trie && key);

    bool found = false;

    if (strlen(key) > 0)
        trie_node_recursive_delete(trie->root, key, &(trie->size), &found);

    return found;
}


bool trie_search(Trie *trie, const char *key, void **ret) {
    assert(trie && key);
    return trie_node_search(trie->root, key, ret);
}


void trie_node_free(TrieNode *node) {

    if (node) {

        if (node->leaf)
            node->leaf = false;
        if (node->ndata && node->ndata->data) {
            free(node->ndata->data);
            free(node->ndata);
        } else if (node->ndata) {
            free(node->ndata);
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
