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

#include <stdlib.h>
#include <string.h>
#include "unit.h"
#include "structures_test.h"
#include "../src/trie.h"
#include "../src/list.h"
#include "../src/ringbuf.h"

/*
 * Tests the creation of a ringbuffer
 */
static char *test_ringbuf_init(void) {
    uint8_t buf[10];
    Ringbuffer *r = ringbuf_init(buf, 10);
    ASSERT("[! ringbuf_init]: ringbuf not created", r != NULL);
    ringbuf_free(r);
    return 0;
}


/*
 * Tests the release of a ringbuffer
 */
static char *test_ringbuf_free(void) {
    uint8_t buf[10];
    Ringbuffer *r = ringbuf_init(buf, 10);
    ringbuf_free(r);
    ASSERT("[! ringbuf_free]: ringbuf not released", r != NULL);
    return 0;
}


/*
 * Tests the full check function of the ringbuffer
 */
static char *test_ringbuf_full(void) {
    uint8_t buf[2];
    Ringbuffer *r = ringbuf_init(buf, 2);
    ASSERT("[! ringbuf_full]: ringbuf_full doesn't work as expected, state ringbuffer is full while being empty", ringbuf_full(r) != 1);
    ringbuf_push(r, 'a');
    ringbuf_push(r, 'b');
    ASSERT("[! ringbuf_full]: ringbuf size %d", ringbuf_size(r));
    ASSERT("[! ringbuf_full]: ringbuf_full doesn't work as expected, state ringbuffer is not full while being full", ringbuf_full(r) == 1);
    ringbuf_free(r);
    return 0;
}


/*
 * Tests the empty check function of the ringbuffer
 */
static char *test_ringbuf_empty(void) {
    uint8_t buf[2];
    Ringbuffer *r = ringbuf_init(buf, 2);
    ASSERT("[! ringbuf_empty]: ringbuf_empty doesn't work as expected, state ringbuffer is not empty while being empty", ringbuf_empty(r) == 1);
    ringbuf_push(r, 'a');
    ASSERT("[! ringbuf_empty]: ringbuf size %d", ringbuf_size(r));
    ASSERT("[! ringbuf_empty]: ringbuf_empty doesn't work as expected, state ringbuffer is empty while having an item", ringbuf_empty(r) != 1);
    ringbuf_free(r);
    return 0;
}


/*
 * Tests the capacity check function of the ringbuffer
 */
static char *test_ringbuf_capacity(void) {
    uint8_t buf[2];
    Ringbuffer *r = ringbuf_init(buf, 2);
    ASSERT("[! ringbuf_capcacity]: ringbuf_capacity doesn't work as expected", ringbuf_capacity(r) == 2);
    ringbuf_free(r);
    return 0;
}


/*
 * Tests the size check function of the ringbuffer
 */
static char *test_ringbuf_size(void) {
    uint8_t buf[2];
    Ringbuffer *r = ringbuf_init(buf, 2);
    ASSERT("[! ringbuf_size]: ringbuf_size doesn't work as expected", ringbuf_size(r) == 0);
    ringbuf_push(r, 'a');
    ASSERT("[! ringbuf_size]: ringbuf_size doesn't work as expected", ringbuf_size(r) == 1);
    ringbuf_free(r);
    return 0;
}


/*
 * Tests the push feature of the ringbuffer
 */
static char *test_ringbuf_push(void) {
    uint8_t buf[2];
    Ringbuffer *r = ringbuf_init(buf, 2);
    ASSERT("[! ringbuf_push]: ringbuf_push doesn't work as expected", ringbuf_size(r) == 0);
    ringbuf_push(r, 'a');
    ASSERT("[! ringbuf_push]: ringbuf_push doesn't work as expected", ringbuf_size(r) == 1);
    uint8_t x;
    ringbuf_pop(r, &x);
    ASSERT("[! ringbuf_push]: ringbuf_push doesn't work as expected", x == 'a');
    ringbuf_free(r);
    return 0;
}


/*
 * Tests the pop feature of the ringbuffer
 */
static char *test_ringbuf_pop(void) {
    uint8_t buf[2];
    Ringbuffer *r = ringbuf_init(buf, 2);
    ASSERT("[! ringbuf_pop]: ringbuf_pop doesn't work as expected", ringbuf_size(r) == 0);
    ringbuf_push(r, 'a');
    ringbuf_push(r, 'b');
    ASSERT("[! ringbuf_pop]: ringbuf_pop doesn't work as expected", ringbuf_size(r) == 2);
    uint8_t x, y;
    ringbuf_pop(r, &x);
    ASSERT("[! ringbuf_pop]: ringbuf_pop doesn't work as expected", x == 'a');
    ringbuf_pop(r, &y);
    ASSERT("[! ringbuf_pop]: ringbuf_pop doesn't work as expected", y == 'b');
    ringbuf_free(r);
    return 0;
}


/*
 * Tests the bulk_push feature of the ringbuffer
 */
static char *test_ringbuf_bulk_push(void) {
    uint8_t buf[3];
    Ringbuffer *r = ringbuf_init(buf, 3);
    ASSERT("[! ringbuf_push]: ringbuf_push doesn't work as expected", ringbuf_size(r) == 0);
    ringbuf_bulk_push(r, (uint8_t *) "abc", 3);
    ASSERT("[! ringbuf_push]: ringbuf_push doesn't work as expected", ringbuf_size(r) == 3);
    uint8_t x;
    ringbuf_pop(r, &x);
    ASSERT("[! ringbuf_push]: ringbuf_push doesn't work as expected", x == 'a');
    ringbuf_free(r);
    return 0;
}


/*
 * Tests the bulk_pop feature of the ringbuffer
 */
static char *test_ringbuf_bulk_pop(void) {
    uint8_t buf[4];
    Ringbuffer *r = ringbuf_init(buf, 4);
    ASSERT("[! ringbuf_bulk_pop]: ringbuf_bulk_pop doesn't work as expected", ringbuf_size(r) == 0);
    ringbuf_bulk_push(r, (uint8_t *) "abc", 3);
    ASSERT("[! ringbuf_bulk_pop]: ringbuf_bulk_pop doesn't work as expected", ringbuf_size(r) == 3);
    uint8_t x[3];
    ringbuf_bulk_pop(r, x, 3);
    ASSERT("[! ringbuf_bulk_pop]: ringbuf_bulk_pop doesn't work as expected", strncmp((const char *) x, "abc", 3) == 0);
    ringbuf_free(r);
    return 0;
}


/*
 * Tests the init feature of the list
 */
static char *test_list_init(void) {
    List *l = list_init();
    ASSERT("[! list_init]: list not created", l != NULL);
    list_free(l, 0);
    return 0;
}


/*
 * Tests the free feature of the list
 */
static char *test_list_free(void) {
    List *l = list_init();
    ASSERT("[! list_free]: list not created", l != NULL);
    list_free(l, 0);
    return 0;
}


/*
 * Tests the push feature of the list
 */
static char *test_list_push(void) {
    List *l = list_init();
    char *x = "abc";
    list_push(l, x);
    ASSERT("[! list_push]: item not pushed in", l->len == 1);
    list_free(l, 0);
    return 0;
}


/*
 * Tests the push_back feature of the list
 */
static char *test_list_push_back(void) {
    List *l = list_init();
    char *x = "abc";
    list_push_back(l, x);
    ASSERT("[! list_push_back]: item not pushed in", l->len == 1);
    list_free(l, 0);
    return 0;
}


/*
 * Tests the creation of a ringbuffer
 */
static char *test_trie_new(void) {
    struct Trie *trie = trie_new();
    ASSERT("[! trie_new]: Trie not created", trie != NULL);
    trie_free(trie);
    return 0;
}


/*
 * Tests the creation of a new node
 */
static char *test_trie_new_node(void) {
    struct TrieNode *node = trie_new_node(NULL, -NOTTL);
    ASSERT("[! trie_new_node]: TrieNode not created", node != NULL);
    trie_node_free(node);
    return 0;
}


/*
 * Tests the insertion on the trie
 */
static char *test_trie_insert(void) {
    struct Trie *root = trie_new();
    const char *key = "hello";
    char *val = strdup("world");
    trie_insert(root, key, val, -NOTTL);
    void *payload = NULL;
    bool found = trie_search(root, key, &payload);
    ASSERT("[! trie_insert]: Trie insertion failed", (found == true && payload != NULL));
    trie_free(root);
    return 0;
}


/*
 * Tests the search on the trie
 */
static char *test_trie_search(void) {
    struct Trie *root = trie_new();
    const char *key = "hello";
    char *val = strdup("world");
    trie_insert(root, key, val, -NOTTL);
    void *payload = NULL;
    bool found = trie_search(root, key, &payload);
    ASSERT("[! trie_search]: Trie search failed", (found == true && payload != NULL));
    trie_free(root);
    return 0;
}


/*
 * Tests the delete on the trie
 */
static char *test_trie_delete(void) {
    struct Trie *root = trie_new();
    const char *key1 = "hello";
    const char *key2 = "hel";
    const char *key3 = "del";
    char *val1 = strdup("world");
    char *val2 = strdup("world");
    char *val3 = strdup("world");
    trie_insert(root, key1, val1, -NOTTL);
    trie_insert(root, key2, val2, -NOTTL);
    trie_insert(root, key3, val3, -NOTTL);
    trie_delete(root, key1);
    trie_delete(root, key2);
    trie_delete(root, key3);
    void *payload = NULL;
    bool found = trie_search(root, key1, &payload);
    ASSERT("[! trie_delete]: Trie delete failed", (found == false || payload == NULL));
    found = trie_search(root, key2, &payload);
    ASSERT("[! trie_delete]: Trie delete failed", (found == false || payload == NULL));
    found = trie_search(root, key3, &payload);
    ASSERT("[! trie_delete]: Trie delete failed", (found == false || payload == NULL));
    trie_free(root);
    return 0;
}

/*
 * Tests the delete on the trie
 */
static char *test_trie_prefix_delete(void) {
    struct Trie *root = trie_new();
    const char *key1 = "hello";
    const char *key2 = "helloworld";
    const char *key3 = "hellot";
    const char *key4 = "hel";
    char *val1 = strdup("world");
    char *val2 = strdup("world");
    char *val3 = strdup("world");
    char *val4 = strdup("world");
    trie_insert(root, key1, val1, -NOTTL);
    trie_insert(root, key2, val2, -NOTTL);
    trie_insert(root, key3, val3, -NOTTL);
    trie_insert(root, key4, val4, -NOTTL);
    trie_prefix_delete(root, key1);
    void *payload = NULL;
    bool found = trie_search(root, key1, &payload);
    ASSERT("[! trie_prefix_delete]: Trie prefix delete key1 failed",
            (found == false || payload == NULL));
    found = trie_search(root, key2, &payload);
    ASSERT("[! trie_prefix_delete]: Trie prefix delete key2 failed",
            (found == false || payload == NULL));
    found = trie_search(root, key3, &payload);
    ASSERT("[! trie_prefix_delete]: Trie prefix delete key3 failed",
            (found == false || payload == NULL));
    found = trie_search(root, key4, &payload);
    ASSERT("[! trie_prefix_delete]: Trie prefix delete key4 success",
            (found == true || payload != NULL));
    trie_free(root);
    return 0;
}



/*
 * All datastructure tests
 */
char *structures_test() {
    RUN_TEST(test_ringbuf_init);
    RUN_TEST(test_ringbuf_free);
    RUN_TEST(test_ringbuf_full);
    RUN_TEST(test_ringbuf_empty);
    RUN_TEST(test_ringbuf_capacity);
    RUN_TEST(test_ringbuf_size);
    RUN_TEST(test_ringbuf_push);
    RUN_TEST(test_ringbuf_pop);
    RUN_TEST(test_ringbuf_bulk_push);
    RUN_TEST(test_ringbuf_bulk_pop);
    RUN_TEST(test_list_init);
    RUN_TEST(test_list_free);
    RUN_TEST(test_list_push);
    RUN_TEST(test_list_push_back);
    RUN_TEST(test_trie_new);
    RUN_TEST(test_trie_new_node);
    RUN_TEST(test_trie_insert);
    RUN_TEST(test_trie_search);
    RUN_TEST(test_trie_delete);
    RUN_TEST(test_trie_prefix_delete);

    return 0;
}
