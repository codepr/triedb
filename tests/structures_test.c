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
#include "../src/util.h"
#include "../src/trie.h"
#include "../src/list.h"
#include "../src/queue.h"
#include "../src/server.h"
#include "../src/cluster.h"
#include "../src/ringbuf.h"
#include "../src/vector.h"
#include "../src/hashtable.h"

/*
 * Tests the creation of a ringbuffer
 */
static char *test_ringbuf_init(void) {
    uint8_t buf[10];
    Ringbuffer *r = ringbuf_init(buf, 10);
    ASSERT("[! ringbuf_init]: ringbuf not created", r != NULL);
    ringbuf_free(r);
    printf(" [ringbuf::ringbuf_init]: OK\n");
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
    printf(" [ringbuf::ringbuf_free]: OK\n");
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
    printf(" [ringbuf::ringbuf_full]: OK\n");
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
    printf(" [ringbuf::ringbuf_empty]: OK\n");
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
    printf(" [ringbuf::ringbuf_capacity]: OK\n");
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
    printf(" [ringbuf::ringbuf_size]: OK\n");
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
    printf(" [ringbuf::ringbuf_push]: OK\n");
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
    printf(" [ringbuf::ringbuf_pop]: OK\n");
    return 0;
}


/*
 * Tests the bulk_push feature of the ringbuffer
 */
static char *test_ringbuf_bulk_push(void) {
    uint8_t buf[3];
    Ringbuffer *r = ringbuf_init(buf, 3);
    ASSERT("[! ringbuf_bulk_push]: ringbuf_bulk_push doesn't work as expected", ringbuf_size(r) == 0);
    ringbuf_bulk_push(r, (uint8_t *) "abc", 3);
    ASSERT("[! ringbuf_bulk_push]: ringbuf_bulk_push doesn't work as expected", ringbuf_size(r) == 3);
    uint8_t x;
    ringbuf_pop(r, &x);
    ASSERT("[! ringbuf_bulk_push]: ringbuf_bulk_push doesn't work as expected", x == 'a');
    ringbuf_free(r);
    printf(" [ringbuf::ringbuf_bulk_push]: OK\n");
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
    printf(" [ringbuf::ringbuf_bulk_pop]: OK\n");
    return 0;
}


/*
 * Tests the init feature of the list
 */
static char *test_list_init(void) {
    List *l = list_init(NULL);
    ASSERT("[! list_init]: list not created", l != NULL);
    list_free(l, 0);
    printf(" [list::list_init]: OK\n");
    return 0;
}


/*
 * Tests the free feature of the list
 */
static char *test_list_free(void) {
    List *l = list_init(NULL);
    ASSERT("[! list_free]: list not created", l != NULL);
    list_free(l, 0);
    printf(" [list::list_free]: OK\n");
    return 0;
}


/*
 * Tests the push feature of the list
 */
static char *test_list_push(void) {
    List *l = list_init(NULL);
    char *x = "abc";
    list_push(l, x);
    ASSERT("[! list_push]: item not pushed in", l->len == 1);
    list_free(l, 0);
    printf(" [list::list_push]: OK\n");
    return 0;
}


/*
 * Tests the push_back feature of the list
 */
static char *test_list_push_back(void) {
    List *l = list_init(NULL);
    char *x = "abc";
    list_push_back(l, x);
    ASSERT("[! list_push_back]: item not pushed in", l->len == 1);
    list_free(l, 0);
    printf(" [list::list_push_back]: OK\n");
    return 0;
}


static int compare_str(void *arg1, void *arg2) {

    const char *tn1 = ((struct list_node *) arg1)->data;
    const char *tn2 = arg2;

    if (strcmp(tn1, tn2) == 0)
        return 0;

    return -1;
}


static char *test_list_remove_node(void) {
    List *l = list_init(NULL);
    char *x = "abc";
    l = list_push(l, x);
    ASSERT("[! list_remove_node :: list_push]: item not pushed in", l->len == 1);
    struct list_node *node = list_remove_node(l, x, compare_str);
    ASSERT("[! list_remove_node]: item not removed", strcmp(node->data, x) == 0);
    tfree(node);
    list_free(l, 0);
    printf(" [list::list_remove_node]: OK\n");
    return 0;
}

/*
 * Tests the creation of a ringbuffer
 */
static char *test_trie_new(void) {
    struct Trie *trie = trie_new();
    ASSERT("[! trie_new]: Trie not created", trie != NULL);
    trie_free(trie);
    printf(" [trie::trie_new]: OK\n");
    return 0;
}


/*
 * Tests the creation of a new node
 */
static char *test_trie_new_node(void) {
    struct trie_node *node = trie_new_node('a');
    size_t size = 0;
    ASSERT("[! trie_new_node]: struct trie_node not created", node != NULL);
    trie_node_free(node, &size);
    printf(" [trie::trie_new_node]: OK\n");
    return 0;
}


/*
 * Tests the insertion on the trie
 */
static char *test_trie_insert(void) {
    struct Trie *root = trie_new();
    const char *key = "hello";
    char *val = "world";
    trie_insert(root, key, val);
    void *payload = NULL;
    bool found = trie_find(root, key, &payload);
    ASSERT("[! trie_insert]: Trie insertion failed", (found == true && payload != NULL));
    trie_free(root);
    printf(" [trie::trie_insert]: OK\n");
    return 0;
}


/*
 * Tests the search on the trie
 */
static char *test_trie_find(void) {
    struct Trie *root = trie_new();
    const char *key = "hello";
    char *val = "world";
    trie_insert(root, key, val);
    void *payload = NULL;
    bool found = trie_find(root, key, &payload);
    ASSERT("[! trie_find]: Trie search failed", (found == true && payload != NULL));
    trie_free(root);
    printf(" [trie::trie_find]: OK\n");
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
    char *val1 = "world";
    char *val2 = "world";
    char *val3 = "world";
    trie_insert(root, key1, val1);
    trie_insert(root, key2, val2);
    trie_insert(root, key3, val3);
    trie_delete(root, key1);
    trie_delete(root, key2);
    trie_delete(root, key3);
    void *payload = NULL;
    bool found = trie_find(root, key1, &payload);
    ASSERT("[! trie_delete]: Trie delete failed", (found == false || payload == NULL));
    found = trie_find(root, key2, &payload);
    ASSERT("[! trie_delete]: Trie delete failed", (found == false || payload == NULL));
    found = trie_find(root, key3, &payload);
    ASSERT("[! trie_delete]: Trie delete failed", (found == false || payload == NULL));
    trie_free(root);
    printf(" [trie::trie_delete]: OK\n");
    return 0;
}

/*
 * Tests the prefix delete on the trie
 */
static char *test_trie_prefix_delete(void) {
    struct Trie *root = trie_new();
    const char *key1 = "hello";
    const char *key2 = "helloworld";
    const char *key3 = "hellot";
    const char *key4 = "hel";
    char *val1 = "world";
    char *val2 = "world";
    char *val3 = "world";
    char *val4 = "world";
    trie_insert(root, key1, val1);
    trie_insert(root, key2, val2);
    trie_insert(root, key3, val3);
    trie_insert(root, key4, val4);
    trie_prefix_delete(root, key1);
    void *payload = NULL;
    bool found = trie_find(root, key1, &payload);
    ASSERT("[! trie_prefix_delete]: Trie prefix delete key1 failed",
            (found == false || payload == NULL));
    found = trie_find(root, key2, &payload);
    ASSERT("[! trie_prefix_delete]: Trie prefix delete key2 failed",
            (found == false || payload == NULL));
    found = trie_find(root, key3, &payload);
    ASSERT("[! trie_prefix_delete]: Trie prefix delete key3 failed",
            (found == false || payload == NULL));
    found = trie_find(root, key4, &payload);
    ASSERT("[! trie_prefix_delete]: Trie prefix delete key4 success",
            (found == true || payload != NULL));
    trie_free(root);
    printf(" [trie::trie_prefix_delete]: OK\n");
    return 0;
}

/*
 * Tests the prefix count on the trie
 */
static char *test_trie_prefix_count(void) {
    struct Trie *root = trie_new();
    const char *key1 = "hello";
    const char *key2 = "helloworld";
    const char *key3 = "hellot";
    const char *key4 = "hel";
    char *val1 = "world";
    char *val2 = "world";
    char *val3 = "world";
    char *val4 = "world";
    trie_insert(root, key1, val1);
    trie_insert(root, key2, val2);
    trie_insert(root, key3, val3);
    trie_insert(root, key4, val4);
    int count = trie_prefix_count(root, "hel");
    ASSERT("[! trie_prefix_count]: Trie prefix count on prefix \"hel\" failed",
            count == 4);
    count = trie_prefix_count(root, "helloworld!");
    ASSERT("[! trie_prefix_count]: Trie prefix count on prefix \"helloworld!\" failed",
            count == 0);
    trie_free(root);
    printf(" [trie::trie_prefix_count]: OK\n");
    return 0;
}

/*
 * Tests the prefix inc on the trie
 */
static char *test_trie_prefix_inc(void) {
    struct Trie *root = trie_new();
    const char *key1 = "key1";
    const char *key2 = "key2";
    const char *key3 = "key3";
    const char *key4 = "key4";

    void *retval1 = NULL, *retval2 = NULL, *retval3 = NULL, *retval4 = NULL;

    char *val1 = "0";
    char *val2 = "1";
    char *val3 = "2";
    char *val4 = "9";

    trie_insert(root, key1, val1);
    trie_insert(root, key2, val2);
    trie_insert(root, key3, val3);
    trie_insert(root, key4, val4);

    // Inc prefix call
    trie_prefix_inc(root, "key");

    // read data
    trie_find(root, key1, &retval1);
    trie_find(root, key2, &retval2);
    trie_find(root, key3, &retval3);
    trie_find(root, key4, &retval4);

    ASSERT("[! trie_prefix_inc]: Trie prefix inc on prefix \"key\" failed",
            strcmp(((struct node_data *) retval1)->data, "1") == 0 &&
            strcmp(((struct node_data *) retval2)->data, "2") == 0 &&
            strcmp(((struct node_data *) retval3)->data, "3") == 0 &&
            strcmp(((struct node_data *) retval4)->data, "10") == 0);

    trie_free(root);
    printf(" [trie::trie_prefix_inc]: OK\n");
    return 0;
}

/*
 * Tests the prefix dec on the trie
 */
static char *test_trie_prefix_dec(void) {
    struct Trie *root = trie_new();
    const char *key1 = "key1";
    const char *key2 = "key2";
    const char *key3 = "key3";
    const char *key4 = "key4";
    void *retval1 = NULL, *retval2 = NULL, *retval3 = NULL, *retval4 = NULL;
    char *val1 = "0";
    char *val2 = "1";
    char *val3 = "2";
    char *val4 = "10";
    trie_insert(root, key1, val1);
    trie_insert(root, key2, val2);
    trie_insert(root, key3, val3);
    trie_insert(root, key4, val4);

    trie_prefix_dec(root, "key");

    // read data
    trie_find(root, key1, &retval1);
    trie_find(root, key2, &retval2);
    trie_find(root, key3, &retval3);
    trie_find(root, key4, &retval4);

    ASSERT("[! trie_prefix_dec]: Trie prefix dec on prefix \"key\" failed",
            strcmp(((struct node_data *) retval1)->data, "-1") == 0 &&
            strcmp(((struct node_data *) retval2)->data, "0") == 0 &&
            strcmp(((struct node_data *) retval3)->data, "1") == 0 &&
            strcmp(((struct node_data *) retval4)->data, "9") == 0);

    trie_free(root);
    printf(" [trie::trie_prefix_dec]: OK\n");
    return 0;
}


static bool compare(void *ptr1, void *ptr2) {

    int *a = ptr1;
    int *b = ptr2;

    if (*a <= *b)
        return true;

    return false;
}


static char *test_vector_init(void) {
    Vector *v = vector_init();
    ASSERT("[! vector_init]: Vector is not properly created", v != NULL);
    vector_free(v);
    printf(" [vector::vector_init]: OK\n");

    return 0;
}


static char *test_vector_free(void) {
    Vector *v = vector_init();
    ASSERT("[! vector_free]: Vector is not properly created", v != NULL);
    vector_free(v);
    // XXX Hack, useless way
    v = NULL;
    ASSERT("[! vector_free]: Vector is not properly freed", v == NULL);
    printf(" [vector::vector_free]: OK\n");

    return 0;
}


static char *test_vector_append(void) {
    Vector *v = vector_init();
    vector_append(v, "hello");
    ASSERT("[! vector_append]: Vector has not appended new item correctly", v->size == 1);
    vector_free(v);
    printf(" [vector::vector_append]: OK\n");

    return 0;
}


static char *test_vector_set(void) {
    Vector *v = vector_init();
    vector_append(v, "hello");
    vector_set(v, 0, "hellonew");
    char *item = vector_get(v, 0);
    ASSERT("[! vector_set]: Vector has not set new item correctly", STREQ(item, "hellonew", 8));
    vector_free(v);
    printf(" [vector::vector_set]: OK\n");

    return 0;
}


static char *test_vector_get(void) {
    Vector *v = vector_init();
    vector_append(v, "hello");
    vector_set(v, 0, "hellonew");
    char *item = vector_get(v, 0);
    ASSERT("[! vector_get]: Vector has not get new item correctly", STREQ(item, "hellonew", 8));
    vector_free(v);
    printf(" [vector::vector_get]: OK\n");

    return 0;
}


static char *test_vector_delete(void) {
    Vector *v = vector_init();
    vector_append(v, "hello");
    vector_set(v, 0, "hellonew");
    char *item = vector_get(v, 0);
    ASSERT("[! vector_delete]: Vector has not set new item correctly", STREQ(item, "hellonew", 8));
    vector_delete(v, 0);
    ASSERT("[! vector_delete]: Vector has not deleted item correctly", v->size == 0);
    vector_free(v);
    printf(" [vector::vector_delete]: OK\n");

    return 0;
}


static char *test_vector_qsort(void) {
    Vector *v = vector_init();
    int n1 = 0;
    vector_append(v, &n1);
    int n2 = n1 + 5;
    vector_append(v, &n2);
    int n3 = n2 - 2;
    vector_append(v, &n3);
    int n4 = n3 + 1;
    vector_append(v, &n4);
    // At this point the vector should contains 0 - 5 - 3 - 4
    vector_qsort(v, compare, sizeof(int));

    ASSERT("[! vector_qsort]: Vector is not correctly sorted",
            *((int *) v->items[0]) == 0 && *((int *) v->items[1]) == 3 && *((int *) v->items[2]) == 4);

    vector_free(v);
    printf(" [vector::vector_qsort]: OK\n");

    return 0;
}

/*
 * Tests the creation of a hashtable
 */
static char *test_hashtable_create(void) {
    HashTable *m = hashtable_create(NULL);
    ASSERT("[! hashtable_create]: hashtable not created", m != NULL);
    hashtable_release(m);
    printf(" [hashtable::hashtable_create]: OK\n");
    return 0;
}


/*
 * Tests the release of a hashtable
 */
static char *test_hashtable_release(void) {
    HashTable *m = hashtable_create(NULL);
    hashtable_release(m);
    printf(" [hashtable::hashtable_release]: OK\n");
    return 0;
}


/*
 * Tests the insertion function of the hashtable
 */
static char *test_hashtable_put(void) {
    HashTable *m = hashtable_create(NULL);
    char *key = "hello";
    char *val = "world";
    int status = hashtable_put(m, key, val);
    ASSERT("[! hashtable_put]: hashtable size = 0", m->size == 1);
    ASSERT("[! hashtable_put]: hashtable_put didn't work as expected", status == HASHTABLE_OK);
    char *val1 = "WORLD";
    hashtable_put(m, tstrdup(key), tstrdup(val1));
    void *ret = hashtable_get(m, key);
    ASSERT("[! hashtable_put]: hashtable_put didn't update the value", strcmp(val1, ret) == 0);
    hashtable_release(m);
    printf(" [hashtable::hashtable_put]: OK\n");
    return 0;
}


/*
 * Tests lookup function of the hashtable
 */
static char *test_hashtable_get(void) {
    HashTable *m = hashtable_create(NULL);
    char *key = "hello";
    char *val = "world";
    hashtable_put(m, tstrdup(key), tstrdup(val));
    char *ret = (char *) hashtable_get(m, key);
    ASSERT("[! hashtable_get]: hashtable_get didn't work as expected", strcmp(ret, val) == 0);
    hashtable_release(m);
    printf(" [hashtable::hashtable_get]: OK\n");
    return 0;
}


/*
 * Tests the deletion function of the hashtable
 */
static char *test_hashtable_del(void) {
    HashTable *m = hashtable_create(NULL);
    char *key = "hello";
    char *val = "world";
    hashtable_put(m, tstrdup(key), tstrdup(val));
    int status = hashtable_del(m, key);
    ASSERT("[! hashtbale_del]: hashtable size = 1", m->size == 0);
    ASSERT("[! hashtbale_del]: hashtbale_del didn't work as expected", status == HASHTABLE_OK);
    hashtable_release(m);
    printf(" [hashtable::hashtable_del]: OK\n");
    return 0;
}


static char *test_cluster_add_new_node(void) {

    struct cluster cluster = { list_init(NULL) };

    struct client client = {
        .ctype = SERVER,
        .addr = "127.0.0.1",
        .fd = -1,
        .last_action_time = 0,
        .ctx_handler = NULL,
        .reply = NULL,
        .request = NULL,
        .response = NULL,
        .db = NULL
    };

    cluster_add_new_node(&cluster, &client, "127.0.0.1", "8080", false);

    ASSERT("[! cluster_add_new_node]: cluster node not correctly added", cluster.nodes->len == 1);

    cluster_add_new_node(&cluster, &client, "127.0.0.1", "8081", false);
    cluster_add_new_node(&cluster, &client, "127.0.0.1", "8082", false);
    cluster_add_new_node(&cluster, &client, "127.0.0.1", "8083", false);

    ASSERT("[! cluster_add_new_node]: cluster node not correctly added", cluster.nodes->len == 4);

    for (struct list_node *ln = cluster.nodes->head; ln; ln = ln->next)
        tfree(ln->data);

    list_free(cluster.nodes, 0);

    printf(" [cluster::cluster_add_new_node]: OK\n");

    return 0;
}


static int compare_upper_bound(void *arg1, void *arg2) {

    /* cast to cluster_node */
    int16_t n1 = ((struct cluster_node *) arg1)->upper_bound;
    int16_t n2 = ((struct cluster_node *) arg2)->upper_bound;

    if (n1 == n2)
        return 0;

    return n1 < n2 ? -1 : 1;
}


static char *test_cluster_get_node(void) {

    struct cluster cluster = { list_init(NULL) };

    struct client client = {
        .ctype = SERVER,
        .addr = "127.0.0.1",
        .fd = -1,
        .last_action_time = 0,
        .ctx_handler = NULL,
        .reply = NULL,
        .request = NULL,
        .db = NULL
    };

    struct cluster_node node1 = { false, 1000, "127.0.0.1", "8080", &client};
    struct cluster_node node2 = { false, 1500, "127.0.0.1", "8080", &client};
    struct cluster_node node3 = { false, 2000, "127.0.0.1", "8080", &client};
    struct cluster_node node4 = { false, 2500, "127.0.0.1", "8080", &client};

    list_push(cluster.nodes, &node1);
    list_push(cluster.nodes, &node2);
    list_push(cluster.nodes, &node3);
    list_push(cluster.nodes, &node4);

    cluster.nodes->head =
        list_merge_sort(cluster.nodes->head, compare_upper_bound);

    struct cluster_node *ret1 = cluster_get_node(&cluster, 768);

    struct cluster_node *ret2 = cluster_get_node(&cluster, 1400);

    struct cluster_node *ret3 = cluster_get_node(&cluster, 2678);

    struct cluster_node *ret4 = cluster_get_node(&cluster, 2000);

    ASSERT("[! cluster_get_node]: did not retrieved the correct node",
            ret1->upper_bound == 1000 &&
            ret2->upper_bound == 1500 &&
            ret3->upper_bound == 1000 &&
            ret4->upper_bound == 2000);

    list_free(cluster.nodes, 0);
    printf(" [cluster::cluster_get_node]: OK\n");

    return 0;
}


static char *test_queue_get(void) {

    Queue *q = queue_create(NULL);

    queue_push(q, "test");

    ASSERT("[! queue_push]: Queue push didn't push item in queue", queue_size(q) == 1);

    char *ret = queue_get(q);

    ASSERT("[! queue_get]: Queue get didn't returned the correct data", STREQ(ret, "test", 5));

    queue_release(q);

    printf(" [queue::queue_get]: OK\n");

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
    RUN_TEST(test_list_remove_node);
    RUN_TEST(test_trie_new);
    RUN_TEST(test_trie_new_node);
    RUN_TEST(test_trie_insert);
    RUN_TEST(test_trie_find);
    RUN_TEST(test_trie_delete);
    RUN_TEST(test_trie_prefix_delete);
    RUN_TEST(test_trie_prefix_count);
    RUN_TEST(test_trie_prefix_inc);
    RUN_TEST(test_trie_prefix_dec);
    RUN_TEST(test_vector_init);
    RUN_TEST(test_vector_free);
    RUN_TEST(test_vector_append);
    RUN_TEST(test_vector_set);
    RUN_TEST(test_vector_get);
    RUN_TEST(test_vector_delete);
    RUN_TEST(test_vector_qsort);
    RUN_TEST(test_hashtable_create);
    RUN_TEST(test_hashtable_put);
    RUN_TEST(test_hashtable_get);
    RUN_TEST(test_hashtable_del);
    RUN_TEST(test_hashtable_release);
    RUN_TEST(test_cluster_add_new_node);
    RUN_TEST(test_cluster_get_node);
    RUN_TEST(test_queue_get);

    return 0;
}
