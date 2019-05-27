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

#include <string.h>
#include <assert.h>
#include "db.h"
#include "trie.h"
#include "util.h"


void database_init(struct database *db, const char *name,
                   trie_destructor *destructor) {
    db->name = name;
    db->data = trie_new(destructor);
}


size_t database_size(const struct database *db) {
    return db->data->size;
}

/*
 * Insert a new key-value pair in the Trie structure, returning a pointer to
 * the new inserted data in order to simplify some operations as the addition
 * of expiring keys with a set TTL.
 */
void database_insert(struct database *db, const char *key,
                     const void *data, short ttl) {
    struct db_item *item = tmalloc(sizeof(*item));
    item->ttl = ttl;
    item->lstime = item->ctime = time(NULL);
    item->data = (void *) data;
    trie_insert(db->data, key, item);
}


/*
 * Returns true if key is present in trie, else false. Also for lookup the
 * big-O runtime is guaranteed O(m) with `m` as length of the key.
 */
bool database_search(const struct database *db, const char *key, void **ret) {
    void *item = NULL;
    bool found = trie_find(db->data, key, &item);
    struct db_item *db_item = item;

    if (!found)
        return false;

    if (db_item->ttl > -1 && db_item->ttl <= (time(NULL) - db_item->ctime))
        // TODO free
        found = false;
    *ret = (found && item) ? db_item : NULL;
    return found;
}

bool database_remove(struct database *db, const char *key) {
    return trie_delete(db->data, key);
}

/*
 * Remove and delete all keys matching a given prefix in the trie
 * e.g. hello*
 * - hello
 * hellot
 * helloworld
 * hello
 */
void database_prefix_remove(struct database *db, const char *prefix) {
    trie_prefix_delete(db->data, prefix);
}

/*
 * Count all keys matching a given prefix in a less than linear time
 * complexity
 */
int database_prefix_count(const struct database *db, const char *prefix) {
    return trie_prefix_count(db->data, prefix);
}

/*
 * Search recursively for all keys matching a given prefix, just a placeholder
 * semantically correct, under the hood it calls for database_prefix_search
 * as well
 */
Vector *database_prefix_keys(const struct database *db, const char *prefix) {
    return trie_prefix_find(db->data, prefix);
}

/* Search for all keys matching a given prefix */
Vector *database_prefix_search(const struct database *db, const char *prefix) {
    return trie_prefix_find(db->data, prefix);
}


static void trie_node_integer_mod(struct trie_node *, int, bool);


static void bst_node_integer_mod(struct bst_node *node, int value, bool inc) {
    if (!node)
        return;
    if (node->left)
        bst_node_integer_mod(node->left, value, inc);
    if (node->right)
        bst_node_integer_mod(node->right, value, inc);
    trie_node_integer_mod(node->data, value, inc);
}


/*
 * Auxiliary function to modify trie values only if they're effectively
 * integers, by adding a quantity or subtracting it
 */
static void trie_node_integer_mod(struct trie_node *node,
                                  int value, bool inc) {

    if (!node)
        return;

    if (trie_is_free_node(node) && !node->data)
        return;

    struct db_item *item = node->data;

    if (item && item->data && is_integer(item->data)) {
        int n = parse_int(item->data);
        n = inc == true ? n + 1 : n - 1;
        // Check for realloc if the new value is "larger" then previous
        char tmp[12];  // max size in bytes
        sprintf(tmp, "%d", n);  // XXX Unsafe
        size_t len = strlen(tmp);
        item->data = trealloc(item->data, len + 1);
        strncpy(item->data, tmp, len + 1);
        item->lstime = time(NULL);
    }

    bst_node_integer_mod(node->children, value, inc);
}

// Add 1 to all integer values matching a given prefix
void database_prefix_inc(struct database *db, const char *prefix) {

    assert(db && db->data && prefix);

    // Walk the trie till the end of the key
    struct trie_node *node = trie_node_find(db->data->root, prefix);

    // No complete key found
    if (!node)
        return;

    // Check all possible sub-paths and add to count where there is a leaf
    trie_node_integer_mod(node, 1, true);
}

// Subtract 1 to all integer values matching a given prefix
void database_prefix_dec(struct database *db, const char *prefix) {

    assert(db && db->data && prefix);

    // Walk the trie till the end of the key
    struct trie_node *node = trie_node_find(db->data->root, prefix);

    // No complete key found
    if (!node)
        return;

    // Check all possible sub-paths and add to count where there is a leaf
    trie_node_integer_mod(node, 1, false);
}


static void trie_node_prefix_set(struct trie_node *, const void *, short);


static void bst_node_prefix_set(struct bst_node *node,
                                const void *val, short ttl) {
    if (!node)
        return;
    if (node->left)
        bst_node_prefix_set(node->left, val, ttl);
    if (node->right)
        bst_node_prefix_set(node->right, val, ttl);
    trie_node_prefix_set(node->data, val, ttl);
}


static void trie_node_prefix_set(struct trie_node *node,
                                 const void *val, short ttl) {

    if (!node)
        return;

    bst_node_prefix_set(node->children, val, ttl);

    struct db_item *item = node->data;
    // mark last node as leaf
    if (item) {
        tfree(item->data);
        item->data = tstrdup(val);
        item->ttl = ttl;
        item->lstime = time(NULL);
    }
}


void database_prefix_set(struct database *db, const char *prefix,
                         const void *val, short ttl) {

    assert(db && db->data && prefix);

    // Walk the trie till the end of the key
    struct trie_node *node = trie_node_find(db->data->root, prefix);

    // No complete key found
    if (!node)
        return;

    // Check all possible sub-paths and add to count where there is a leaf
    trie_node_prefix_set(node, val, ttl);
}


static void trie_node_prefix_ttl(struct trie_node *, short );


static void bst_node_prefix_ttl(struct bst_node *node, short ttl) {
    if (!node)
        return;
    if (node->left)
        bst_node_prefix_ttl(node->left, ttl);
    if (node->right)
        bst_node_prefix_ttl(node->right, ttl);
    trie_node_prefix_ttl(node->data, ttl);
}


static void trie_node_prefix_ttl(struct trie_node *node, short ttl) {

    if (!node)
        return;

    bst_node_prefix_ttl(node->children, ttl);

    struct db_item *item = node->data;
    // mark last node as leaf
    if (item && item->data) {
        item->ttl = ttl;
        item->lstime = time(NULL);
    }
}


void database_prefix_ttl(struct database *db, const char *prefix, short ttl) {

    assert(db && db->data && prefix);

    // Walk the trie till the end of the key
    struct trie_node *node = trie_node_find(db->data->root, prefix);

    // No complete key found
    if (!node)
        return;

    // Check all possible sub-paths and add to count where there is a leaf
    trie_node_prefix_ttl(node, ttl);
}


void database_flush(struct database *db) {
    assert(db);
    trie_node_destroy(db->data->root, &db->data->size, db->data->destructor);
}
