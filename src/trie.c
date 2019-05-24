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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "trie.h"
#include "util.h"


static void children_destroy(struct bst_node *, size_t *);

/*
 * Check for children in a struct trie_node, if a node has no children is
 * considered free
 */
bool trie_is_free_node(const struct trie_node *node) {
    return !node->children ? true : false;
}


struct trie_node *trie_node_find(const struct trie_node *node,
                                 const char *prefix) {

    if (!node)
        return NULL;

    struct trie_node *retnode = (struct trie_node *) node;

    // Move to the end of the prefix first
    for (; *prefix; ++prefix) {

        // O(n), the best we can have
        struct bst_node *child = bst_search(retnode->children, *prefix);

        // No key with the full prefix in the trie
        if (!child)
            return NULL;

        retnode = child->data;
    }

    return retnode;
}


static int trie_node_count(const struct trie_node *);


static int trie_children_count(const struct bst_node *node) {
    if (!node)
        return 0;
    return trie_node_count(node->data)
        + trie_children_count(node->left)
        + trie_children_count(node->right);
}


static int trie_node_count(const struct trie_node *node) {

    if (!node)
        return 0;

    if (node->data)
        return 1 + trie_children_count(node->children);
    else
        return trie_children_count(node->children);
}


// Returns new trie node (initialized to NULL)
struct trie_node *trie_create_node(char c) {

    struct trie_node *new_node = tmalloc(sizeof(*new_node));

    if (new_node) {

        new_node->chr = c;
        new_node->data = NULL;
        new_node->children = NULL;
    }

    return new_node;
}

// Returns new Trie, with a NULL root and 0 size
Trie *trie_new(int (*destructor)(struct trie_node *)) {
    Trie *trie = tmalloc(sizeof(*trie));
    trie_init(trie, destructor);
    return trie;
}


void trie_init(Trie *trie, int (*destructor)(struct trie_node *)) {
    trie->root = trie_create_node('\0');
    trie->size = 0;
    trie->destructor = destructor;
}


size_t trie_size(const Trie *trie) {
    return trie->size;
}

/*
 * If not present, inserts key into trie, if the key is prefix of trie node,
 * just marks leaf node by assigning the new data pointer. Returns a pointer
 * to the new inserted data.
 *
 * Being a Trie, it should guarantees O(m) performance for insertion on the
 * worst case, where `m` is the length of the key.
 */
static struct node_data *trie_node_insert(struct trie_node *root,
                                          const char *key,
                                          const void *data, size_t *size) {

    struct trie_node *cursor = root;
    struct trie_node *cur_node = NULL;
    struct bst_node *tmp = NULL;

    // Iterate through the key char by char
    for (; *key; key++) {

        /*
         * We can use a linear search as on a linked list O(n) is the best find
         * algorithm we can use, as binary search would have the same if not
         * worse performance by not having direct access to node like in an
         * array.
         *
         * Anyway we expect to have an average O(n/2) cause at every insertion
         * the list is sorted so we expect to find our char in the middle on
         * average.
         *
         * As a future improvement it's advisable to substitute list with a
         * B-tree or RBTree to improve searching complexity to O(logn) at best,
         * avg and worst while maintaining O(n) space complexity, but it really
         * depends also on the size of the alphabet.
         */
        tmp = bst_search(cursor->children, *key);

        // No match, we add a new node and sort the list with the new added link
        if (!tmp) {
            cur_node = trie_create_node(*key);
            cursor->children = bst_insert(cursor->children, *key, cur_node);
        } else {
            // Match found, no need to sort the list, the child already exists
            cur_node = tmp->data;
        }
        cursor = cur_node;
    }

    /*
     * Clear out if already taken (e.g. we are in a leaf node), rc = 0 to not
     * change the trie size, otherwise 1 means that we added a new node,
     * effectively changing the size
     */
    if (!cursor->data)
        (*size)++;

    cursor->data = (void *) data;

    return cursor->data;
}

/*
 * Returns true if key is present in trie, else false. Also for lookup the
 * big-O runtime is guaranteed O(m) with `m` as length of the key.
 */
static bool trie_node_search(const struct trie_node *root,
                             const char *key, void **ret) {

    // Walk the trie till the end of the key
    struct trie_node *cursor = trie_node_find(root, key);

    *ret = (cursor && cursor->data) ? cursor->data : NULL;

    // Return false if no complete key found, true otherwise
    return !*ret ? false : true;
}

/*
 * Insert a new key-value pair in the Trie structure, returning a pointer to
 * the new inserted data in order to simplify some operations as the addition
 * of expiring keys with a set TTL.
 */
struct node_data *trie_insert(Trie *trie, const char *key, const void *data) {

    assert(trie && key);

    return trie_node_insert(trie->root, key, data, &trie->size);
}


bool trie_delete(Trie *trie, const char *key) {

    assert(trie && key);

    if (strlen(key) > 0) {
        struct trie_node *retnode = (struct trie_node *) trie->root;
        // Move to the end of the prefix first
        for (; *key; ++key) {

            // O(n), the best we can have
            struct bst_node *child = bst_search(retnode->children, *key);

            // No key with the full prefix in the trie
            if (!child)
                return false;

            retnode = child->data;

        }
        if (retnode->data) {
            tfree(retnode->data);
            retnode->data = NULL;
        }
        return true;
    }

    return false;
}


bool trie_find(const Trie *trie, const char *key, void **ret) {
    assert(trie && key);
    return trie_node_search(trie->root, key, ret);
}

/*
 * Remove and delete all keys matching a given prefix in the trie
 * e.g. hello*
 * - hello
 * hellot
 * helloworld
 * hello
 */
void trie_prefix_delete(Trie *trie, const char *prefix) {

    assert(trie && prefix);

    // Walk the trie till the end of the key
    struct trie_node *cursor = trie_node_find(trie->root, prefix);

    // No complete key found
    if (!cursor)
        return;

    // Simply remove the key if it has no children, no need to clear the list
    if (trie_is_free_node(cursor)) {
        trie_delete(trie, prefix);
        return;
    }

    children_destroy(cursor->children, &trie->size);
    cursor->children = NULL;

    trie_delete(trie, prefix);
}


int trie_prefix_count(const Trie *trie, const char *prefix) {

    assert(trie && prefix);

    int count = 0;

    // Walk the trie till the end of the key
    struct trie_node *node = trie_node_find(trie->root, prefix);

    // No complete key found
    if (!node)
        return count;

    // Check all possible sub-paths and add to count where there is a leaf */
    count += trie_node_count(node);

    return count;
}


static void trie_node_prefix_find(const struct trie_node *,
                                  char *, int , Vector *);


static void children_prefix_find(const struct bst_node *node,
                                 char str[], int level, Vector *keys) {
    trie_node_prefix_find(node->data, str, level, keys);
    if (node->left)
        children_prefix_find(node->left, str, level, keys);
    if (node->right)
        children_prefix_find(node->right, str, level, keys);
}


static void trie_node_prefix_find(const struct trie_node *node,
                                  char str[], int level, Vector *keys) {

    if (!node)
        return;

    /*
     * If NON NULL child is found add parent key to str and call the function
     * recursively for child node, caring for the size of the current string,
     * if exceed bounds, double the size of the string host
     */
    if (level == malloc_size(str))
        str = trealloc(str, level * 2);
    str[level] = node->chr;

    /*
     * If node is leaf node, it indicates end of string, so a null charcter is
     * added and string is added to the keys list
     */
    if (node->data) {
        str[level + 1] = '\0';
        struct kv_obj *kv = tmalloc(sizeof(*kv));
        kv->key = tstrdup(str);
        kv->data = node->data;
        vector_append(keys, kv);
    }

    if (node->children)
        children_prefix_find(node->children, str, level + 1, keys);
}


Vector *trie_prefix_find(const Trie *trie, const char *prefix) {

    assert(trie && prefix);

    // Walk the trie till the end of the key
    struct trie_node *node = trie_node_find(trie->root, prefix);

    // No complete key found
    if (!node)
        return NULL;

    Vector *keys = vector_new(NULL);

    // Check all possible sub-paths and add the resulting key to the result
    char *str = tmalloc(32);
    size_t plen = strlen(prefix);
    memcpy(str, prefix, plen);
    str[plen] = '\0';

    /*
     * Recursive function call, starting from index - 1, starting saving nodes
     * from the last character explored
     */
    trie_node_prefix_find(node, str, plen - 1, keys);

    tfree(str);

    return keys;
}


static void children_destroy(struct bst_node *node, size_t *len) {
    if (!node)
        return;
    trie_node_destroy(node->data, len);
    if (node->left)
        children_destroy(node->left,len);
    if (node->right)
        children_destroy(node->right, len);
    tfree(node);
}

/* Release memory of a node while updating size of the trie */
void trie_node_destroy(struct trie_node *node, size_t *size) {

    // Base case
    if (!node)
        return;

    // Recursive call to all children of the node
    children_destroy(node->children, size);
    node->children = NULL;

    // Release memory on data stored on the node
    if (node->data) {
        tfree(node->data);
        node->data = NULL;
        if (*size > 0)
            (*size)--;
    }

    // Release the node itself
    tfree(node);
}


void trie_destroy(Trie *trie) {

    if (!trie)
        return;

    trie_node_destroy(trie->root, &(trie->size));

    tfree(trie);
}
