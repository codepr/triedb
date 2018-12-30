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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "trie.h"
#include "util.h"


/* Auxiliary comparison function, uses on list searches, this one compare the
 * char field stored in each TrieNode structure contained in each node of the
 * list.
 */
 static int with_char(void *arg1, void *arg2) {

    TrieNode *tn1 = ((ListNode *) arg1)->data;
    TrieNode *tn2 = ((ListNode *) arg2)->data;

    if (tn1->chr == tn2->chr)
        return 0;

    return -1;
}

// Check for children in a TrieNode, if a node has no children is considered
// free
static bool trie_is_free_node(TrieNode *node) {
    return node->children->len == 0 ? true : false;
}


static TrieNode *trie_node_find(TrieNode *node, const char *prefix) {

    const char *k = prefix;

    // Move to the end of the prefix first
    for (char c = *k; c != '\0'; c = *(++k)) {

        // O(n), the best we can have
        ListNode *child = linear_search(node->children, c);

        // No key with the full prefix in the trie
        if (!child)
            return NULL;

        node = child->data;
    }

    return node;
}


static int trie_node_count(TrieNode *node) {

    if (trie_is_free_node(node))
        return 1;

    int count = 0;

    for (ListNode *cur = node->children->head; cur; cur = cur->next)
        count += trie_node_count(cur->data);

    if (node->ndata)
        count++;

    return count;
}


// Returns new trie node (initialized to NULL)
TrieNode *trie_new_node(char c) {

    TrieNode *new_node = tmalloc(sizeof(*new_node));

    if (new_node) {

        new_node->chr = c;
        new_node->ndata = NULL;
        new_node->children = list_init();
    }

    return new_node;
}

// Returns new Trie, with a NULL root and 0 size
Trie *trie_new(void) {
    Trie *trie = tmalloc(sizeof(*trie));
    trie->root = trie_new_node(' ');
    trie->size = 0;
    return trie;
}

/* If not present, inserts key into trie, if the key is prefix of trie node,
   just marks leaf node.

   Being a Trie, it should guarantees O(m) performance for insertion on the
   worst case, where `m` is the length of the key. */
static int trie_node_insert(TrieNode *root,
        const char *key, void *data, int16_t ttl) {

    int rc = 0;
    const char *k = key;

    TrieNode *cursor = root;
    TrieNode *cur_node = NULL;
    ListNode *tmp = NULL;

    // Iterate through the key char by char
    for (char x = *k; x != '\0'; x = *(++k)) {

        /* We can use a linear search as on a linked list O(n) is the best find
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
        tmp = linear_search(cursor->children, x);

        // No match, we add a new node and sort the list with the new added link
        if (!tmp) {
            cur_node = trie_new_node(x);
            cursor->children = list_push(cursor->children, cur_node);
            cursor->children->head = merge_sort_tnode(cursor->children->head);
        } else {
            // Match found, no need to sort the list, the child already exists
            cur_node = tmp->data;
        }
        cursor = cur_node;
    }

    /* Clear out if already taken (e.g. we are in a leaf node), rc = 0 to not
     * change the trie size, otherwise 1 means that we added a new node,
     * effectively changing the size
     */
    if (cursor->ndata)
        tfree(cursor->ndata->data);
    else
        rc = 1;

    // mark last node as leaf
    cursor->ndata = tmalloc(sizeof(struct NodeData));
    cursor->ndata->data = data;
    cursor->ndata->ttl = ttl;

    return rc;
}

/* Private function, iterate recursively through the trie structure starting
   from a given node, deleting the target value */
static bool trie_node_recursive_delete(TrieNode *node,
        const char *key, size_t *size, bool *found) {

    if (!node)
        return false;

    // Base case
    if (*key == '\0') {

        if (node->ndata) {

            // Update trie size
            (*size)--;

            // Update found flag
            *found = true;

            // Free resources, covering the case of a sub-prefix
            if (node->ndata->data) {
                tfree(node->ndata->data);
                node->ndata->data = NULL;
            }
            tfree(node->ndata);
            node->ndata = NULL;

            // If empty, node to be deleted
            return trie_is_free_node(node);
        }

    } else {

        // O(n), the best we can have
        ListNode *cur = linear_search(node->children, *key);

        if (!cur)
            return false;

        TrieNode *child = cur->data;

        if (trie_node_recursive_delete(child, key + 1, size, found)) {

            // Messy solution, requiring probably avoidable allocations
            TrieNode t = {*key, NULL, NULL};
            ListNode tmp = {&t, NULL};
            list_remove(node->children, &tmp, with_char);

            // last node marked, delete it
            trie_node_free(child);

            // recursively climb up, and delete eligible nodes
            return (!node->ndata && trie_is_free_node(node));
        }
    }

    return false;
}

/* Returns true if key is present in trie, else false. Also for lookup the
   big-O runtime is guaranteed O(m) with `m` as length of the key. */
static bool trie_node_search(TrieNode *root, const char *key, void **ret) {

    // Walk the trie till the end of the key
    TrieNode *cursor = trie_node_find(root, key);

    *ret = (cursor && cursor->ndata) ? cursor->ndata : NULL;

    // No complete key found
    if (!*ret)
        return false;

    return true;

}

/* Insert a new key-value pair in the Trie structure */
void trie_insert(Trie *trie, const char *key, void *data, int16_t ttl) {

    assert(trie && key);

    if (trie_node_insert(trie->root, key, data, ttl) == 1)
        trie->size++;
}


bool trie_delete(Trie *trie, const char *key) {

    assert(trie && key);

    bool found = false;

    if (strlen(key) > 0)
        trie_node_recursive_delete(trie->root, key, &(trie->size), &found);

    return found;
}


bool trie_find(Trie *trie, const char *key, void **ret) {
    assert(trie && key);
    return trie_node_search(trie->root, key, ret);
}

/* Remove and delete all keys matching a given prefix in the trie
   e.g. hello*
   - hello
   hellot
   helloworld
   hello
   */
void trie_prefix_delete(Trie *trie, const char *prefix) {

    assert(trie && prefix);

    // Walk the trie till the end of the key
    TrieNode *cursor = trie_node_find(trie->root, prefix);

    // No complete key found
    if (!cursor)
        return;

    /* ListNode *rm = NULL; */

    // Clear out all possible sub-paths
    for (ListNode *cur = cursor->children->head; cur; cur = cur->next) {
        trie_node_free(cur->data);
        cur->data = NULL;
        trie->size--;
    }

    // Set the current node (the one storing the last character of the prefix)
    // as a leaf and delete the prefix key as well
    trie_delete(trie, prefix);

    list_clear(cursor->children, 1);
}


int trie_prefix_count(Trie *trie, const char *prefix) {

    assert(trie && prefix);

    int count = 0;

    // Walk the trie till the end of the key
    TrieNode *cursor = trie_node_find(trie->root, prefix);

    // No complete key found
    if (!cursor)
        return count;

    // Check all possible sub-paths and add to count where there is a leaf */
    count += trie_node_count(cursor);

    return count;
}

/* Auxiliary function to modify trie values only if they're effectively
 * integers, by adding a quantity or subtracting it */
static void trie_node_integer_mod(TrieNode *node, int value, bool inc) {

    if (trie_is_free_node(node) && !node->ndata)
        return;

    if (node->ndata && is_integer(node->ndata->data)) {
        int n = parse_int(node->ndata->data);
        n = inc == true ? n + 1 : n - 1;
        // Check for realloc if the new value is "larger" then previous
        char tmp[12];  // max size in bytes
        sprintf(tmp, "%d", n);  // XXX Unsafe
        size_t len = strlen(tmp);
        node->ndata->data = trealloc(node->ndata->data, len + 1);
        strncpy(node->ndata->data, tmp, len + 1);
    }

    for (ListNode *cur = node->children->head; cur; cur = cur->next)
        trie_node_integer_mod(((TrieNode *) cur->data), value, inc);

}

// Add 1 to all integer values matching a given prefix
void trie_prefix_inc(Trie *trie, const char *prefix) {

    assert(trie && prefix);

    // Walk the trie till the end of the key
    TrieNode *cursor = trie_node_find(trie->root, prefix);

    // No complete key found
    if (!cursor)
        return;

    // Check all possible sub-paths and add to count where there is a leaf
    trie_node_integer_mod(cursor, 1, true);
}

// Subtract 1 to all integer values matching a given prefix
void trie_prefix_dec(Trie *trie, const char *prefix) {

    assert(trie && prefix);

    // Walk the trie till the end of the key
    TrieNode *cursor = trie_node_find(trie->root, prefix);

    // No complete key found
    if (!cursor)
        return;

    // Check all possible sub-paths and add to count where there is a leaf
    trie_node_integer_mod(cursor, 1, false);
}


void trie_node_free(TrieNode *node) {

    if (!node)
        return;

    if (node->children) {
        for (ListNode *cur = node->children->head; cur; cur = cur->next)
            trie_node_free(cur->data);
        list_free(node->children, 0);
    }

    if (node->ndata && node->ndata->data) {
        tfree(node->ndata->data);
        tfree(node->ndata);

    } else if (node->ndata) {
        tfree(node->ndata);
    }

    tfree(node);
}


void trie_free(Trie *trie) {
    if (!trie)
        return;
    trie_node_free(trie->root);
    tfree(trie);
}
