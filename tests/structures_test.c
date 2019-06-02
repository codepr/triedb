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
#include "../src/db.h"
#include "../src/util.h"
#include "../src/trie.h"
#include "../src/list.h"
#include "../src/server.h"
#include "../src/cluster.h"
#include "../src/vector.h"
#include "../src/hashtable.h"


/*
 * Tests the init feature of the list
 */
static char *test_list_new(void) {
    List *l = list_new(NULL);
    ASSERT("[! list_create]: list not created", l != NULL);
    list_destroy(l, 0);
    printf(" [list::list_create]: OK\n");
    return 0;
}


/*
 * Tests the free feature of the list
 */
static char *test_list_destroy(void) {
    List *l = list_new(NULL);
    ASSERT("[! list_release]: list not created", l != NULL);
    list_destroy(l, 0);
    printf(" [list::list_release]: OK\n");
    return 0;
}


/*
 * Tests the push feature of the list
 */
static char *test_list_push(void) {
    List *l = list_new(NULL);
    char *x = "abc";
    list_push(l, x);
    ASSERT("[! list_push]: item not pushed in", l->len == 1);
    list_destroy(l, 0);
    printf(" [list::list_push]: OK\n");
    return 0;
}


/*
 * Tests the push_back feature of the list
 */
static char *test_list_push_back(void) {
    List *l = list_new(NULL);
    char *x = "abc";
    list_push_back(l, x);
    ASSERT("[! list_push_back]: item not pushed in", l->len == 1);
    list_destroy(l, 0);
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
    List *l = list_new(NULL);
    char *x = "abc";
    l = list_push(l, x);
    ASSERT("[! list_remove_node :: list_push]: item not pushed in", l->len == 1);
    struct list_node *node = list_remove_node(l, x, compare_str);
    ASSERT("[! list_remove_node]: item not removed", strcmp(node->data, x) == 0);
    tfree(node);
    list_destroy(l, 0);
    printf(" [list::list_remove_node]: OK\n");
    return 0;
}

/*
 * Tests the creation of a ringbuffer
 */
static char *test_trie_new(void) {
    struct Trie *trie = trie_new(NULL);
    ASSERT("[! trie_create]: Trie not created", trie != NULL);
    trie_destroy(trie);
    printf(" [trie::trie_create]: OK\n");
    return 0;
}


/*
 * Tests the creation of a new node
 */
static char *test_trie_create_node(void) {
    struct trie_node *node = trie_create_node('a');
    size_t size = 0;
    ASSERT("[! trie_create_node]: struct trie_node not created", node != NULL);
    trie_node_destroy(node, &size, NULL);
    printf(" [trie::trie_create_node]: OK\n");
    return 0;
}


/*
 * Tests the insertion on the trie
 */
static char *test_trie_insert(void) {
    struct Trie *root = trie_new(NULL);
    const char *key = "hello";
    char *val = "world";
    trie_insert(root, key, tstrdup(val));
    void *payload = NULL;
    bool found = trie_find(root, key, &payload);
    ASSERT("[! trie_insert]: Trie insertion failed",
           (found == true && payload != NULL));
    trie_destroy(root);
    printf(" [trie::trie_insert]: OK\n");
    return 0;
}


/*
 * Tests the search on the trie
 */
static char *test_trie_find(void) {
    struct Trie *root = trie_new(NULL);
    const char *key = "hello";
    char *val = "world";
    trie_insert(root, key, tstrdup(val));
    void *payload = NULL;
    bool found = trie_find(root, key, &payload);
    ASSERT("[! trie_find]: Trie search failed",
           (found == true && payload != NULL));
    trie_destroy(root);
    printf(" [trie::trie_find]: OK\n");
    return 0;
}


/*
 * Tests the delete on the trie
 */
static char *test_trie_delete(void) {
    struct Trie *root = trie_new(NULL);
    const char *key1 = "hello";
    const char *key2 = "hel";
    const char *key3 = "del";
    char *val1 = "world";
    char *val2 = "world";
    char *val3 = "world";
    trie_insert(root, key1, tstrdup(val1));
    trie_insert(root, key2, tstrdup(val2));
    trie_insert(root, key3, tstrdup(val3));
    trie_delete(root, key1);
    trie_delete(root, key2);
    trie_delete(root, key3);
    void *payload = NULL;
    bool found = trie_find(root, key1, &payload);
    ASSERT("[! trie_delete]: Trie delete failed",
           (found == false || payload == NULL));
    found = trie_find(root, key2, &payload);
    ASSERT("[! trie_delete]: Trie delete failed",
           (found == false || payload == NULL));
    found = trie_find(root, key3, &payload);
    ASSERT("[! trie_delete]: Trie delete failed",
           (found == false || payload == NULL));
    trie_destroy(root);
    printf(" [trie::trie_delete]: OK\n");
    return 0;
}

/*
 * Tests the prefix delete on the trie
 */
static char *test_trie_prefix_delete(void) {
    struct Trie *root = trie_new(NULL);
    const char *key1 = "hello";
    const char *key2 = "helloworld";
    const char *key3 = "hellot";
    const char *key4 = "hel";
    char *val1 = "world";
    char *val2 = "world";
    char *val3 = "world";
    char *val4 = "world";
    trie_insert(root, key1, tstrdup(val1));
    trie_insert(root, key2, tstrdup(val2));
    trie_insert(root, key3, tstrdup(val3));
    trie_insert(root, key4, tstrdup(val4));
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
    trie_destroy(root);
    printf(" [trie::trie_prefix_delete]: OK\n");
    return 0;
}

/*
 * Tests the prefix count on the trie
 */
static char *test_trie_prefix_count(void) {
    struct Trie *root = trie_new(NULL);
    const char *key1 = "hello";
    const char *key2 = "helloworld";
    const char *key3 = "hellot";
    const char *key4 = "hel";
    char *val1 = "world";
    char *val2 = "world";
    char *val3 = "world";
    char *val4 = "world";
    trie_insert(root, key1, tstrdup(val1));
    trie_insert(root, key2, tstrdup(val2));
    trie_insert(root, key3, tstrdup(val3));
    trie_insert(root, key4, tstrdup(val4));
    int count = trie_prefix_count(root, "hel");
    ASSERT("[! trie_prefix_count]: Trie prefix count on prefix \"hel\" failed",
            count == 4);
    count = trie_prefix_count(root, "helloworld!");
    ASSERT("[! trie_prefix_count]: Trie prefix count on prefix \"helloworld!\" failed",
            count == 0);
    trie_destroy(root);
    printf(" [trie::trie_prefix_count]: OK\n");
    return 0;
}


static inline bool trie_node_destructor(struct trie_node *node,
                                        bool dataonly) {
    bool ret = false;

    if (!node)
        return ret;

    struct db_item *item = node->data;

    if (!item)
        goto exit;

    if (item->data) {
        tfree(item->data);
        item->data = NULL;
    }

    tfree(node->data);
    node->data = NULL;

    ret = true;

exit:

    if (dataonly == false)
        tfree(node);

    return ret;
}

/*
 * Tests the prefix inc on the trie
 */
static char *test_database_prefix_inc(void) {
    struct database db;
    database_init(&db, "test", trie_node_destructor);
    struct Trie *root = db.data;
    const char *key1 = "key1";
    const char *key2 = "key2";
    const char *key3 = "key3";
    const char *key4 = "key4";

    void *retval1 = NULL, *retval2 = NULL, *retval3 = NULL, *retval4 = NULL;

    char *val1 = "0";
    char *val2 = "1";
    char *val3 = "2";
    char *val4 = "9";

    database_insert(&db, key1, tstrdup(val1), -1);
    database_insert(&db, key2, tstrdup(val2), -1);
    database_insert(&db, key3, tstrdup(val3), -1);
    database_insert(&db, key4, tstrdup(val4), -1);

    // Inc prefix call
    database_prefix_inc(&db, "key");

    // read data
    database_search(&db, key1, &retval1);
    database_search(&db, key2, &retval2);
    database_search(&db, key3, &retval3);
    database_search(&db, key4, &retval4);

    struct db_item *item1 = (struct db_item *) retval1;
    struct db_item *item2 = (struct db_item *) retval2;
    struct db_item *item3 = (struct db_item *) retval3;
    struct db_item *item4 = (struct db_item *) retval4;

    ASSERT("[! trie_prefix_inc]: Trie prefix inc on prefix \"key\" failed",
            strcmp(item1->data, "1") == 0 && strcmp(item2->data, "2") == 0 &&
            strcmp(item3->data, "3") == 0 && strcmp(item4->data, "10") == 0);

    trie_destroy(root);
    printf(" [trie::trie_prefix_inc]: OK\n");
    return 0;
}

/*
 * Tests the prefix dec on the trie
 */
static char *test_trie_prefix_dec(void) {
    struct database db;
    database_init(&db, "test", trie_node_destructor);
    struct Trie *root = db.data;
    const char *key1 = "key1";
    const char *key2 = "key2";
    const char *key3 = "key3";
    const char *key4 = "key4";

    void *retval1 = NULL, *retval2 = NULL, *retval3 = NULL, *retval4 = NULL;

    char *val1 = "0";
    char *val2 = "1";
    char *val3 = "2";
    char *val4 = "10";

    database_insert(&db, key1, tstrdup(val1), -1);
    database_insert(&db, key2, tstrdup(val2), -1);
    database_insert(&db, key3, tstrdup(val3), -1);
    database_insert(&db, key4, tstrdup(val4), -1);

    database_prefix_dec(&db, "key");

    // read data
    database_search(&db, key1, &retval1);
    database_search(&db, key2, &retval2);
    database_search(&db, key3, &retval3);
    database_search(&db, key4, &retval4);

    struct db_item *item1 = (struct db_item *) retval1;
    struct db_item *item2 = (struct db_item *) retval2;
    struct db_item *item3 = (struct db_item *) retval3;
    struct db_item *item4 = (struct db_item *) retval4;

    ASSERT("[! trie_prefix_dec]: Trie prefix dec on prefix \"key\" failed",
            strcmp(item1->data, "-1") == 0 && strcmp(item2->data, "0") == 0 &&
            strcmp(item3->data, "1") == 0 && strcmp(item4->data, "9") == 0);

    trie_destroy(root);
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


static char *test_vector_new(void) {
    Vector *v = vector_new(NULL);
    ASSERT("[! vector_create]: Vector is not properly created", v != NULL);
    vector_destroy(v);
    printf(" [vector::vector_create]: OK\n");

    return 0;
}


static char *test_vector_destroy(void) {
    Vector *v = vector_new(NULL);
    ASSERT("[! vector_release]: Vector is not properly created", v != NULL);
    vector_destroy(v);
    // XXX Hack, useless way
    v = NULL;
    ASSERT("[! vector_release]: Vector is not properly freed", v == NULL);
    printf(" [vector::vector_release]: OK\n");

    return 0;
}


static char *test_vector_append(void) {
    Vector *v = vector_new(NULL);
    vector_append(v, tstrdup("hello"));
    ASSERT("[! vector_append]: Vector has not appended new item correctly",
           v->size == 1);
    vector_destroy(v);
    printf(" [vector::vector_append]: OK\n");

    return 0;
}


static char *test_vector_set(void) {
    Vector *v = vector_new(NULL);
    vector_append(v, "hello");
    vector_set(v, 0, tstrdup("hellonew"));
    char *item = vector_get(v, 0);
    ASSERT("[! vector_set]: Vector has not set new item correctly",
           STREQ(item, "hellonew", 8));
    vector_destroy(v);
    printf(" [vector::vector_set]: OK\n");

    return 0;
}


static char *test_vector_get(void) {
    Vector *v = vector_new(NULL);
    vector_append(v, "hello");
    vector_set(v, 0, tstrdup("hellonew"));
    char *item = vector_get(v, 0);
    ASSERT("[! vector_get]: Vector has not get new item correctly",
           STREQ(item, "hellonew", 8));
    vector_destroy(v);
    printf(" [vector::vector_get]: OK\n");

    return 0;
}


static char *test_vector_delete(void) {
    Vector *v = vector_new(NULL);
    vector_append(v, "hello");
    vector_set(v, 0, "hellonew");
    char *item = vector_get(v, 0);
    ASSERT("[! vector_delete]: Vector has not set new item correctly",
           STREQ(item, "hellonew", 8));
    vector_delete(v, 0);
    ASSERT("[! vector_delete]: Vector has not deleted item correctly",
           v->size == 0);
    vector_destroy(v);
    printf(" [vector::vector_delete]: OK\n");

    return 0;
}


static char *test_vector_qsort(void) {
    Vector *v = vector_new(NULL);
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

    tfree(v->items);
    tfree(v);
    printf(" [vector::vector_qsort]: OK\n");

    return 0;
}

/*
 * Tests the creation of a hashtable
 */
static char *test_hashtable_new(void) {
    HashTable *m = hashtable_new(NULL);
    ASSERT("[! hashtable_create]: hashtable not created", m != NULL);
    hashtable_destroy(m);
    printf(" [hashtable::hashtable_create]: OK\n");
    return 0;
}


/*
 * Tests the release of a hashtable
 */
static char *test_hashtable_destroy(void) {
    HashTable *m = hashtable_new(NULL);
    hashtable_destroy(m);
    printf(" [hashtable::hashtable_release]: OK\n");
    return 0;
}


/*
 * Tests the insertion function of the hashtable
 */
static char *test_hashtable_put(void) {
    HashTable *m = hashtable_new(NULL);
    char *key = "hello";
    char *val = "world";
    int status = hashtable_put(m, key, val);
    ASSERT("[! hashtable_put]: hashtable size = 0", m->size == 1);
    ASSERT("[! hashtable_put]: hashtable_put didn't work as expected",
           status == HASHTABLE_OK);
    char *val1 = "WORLD";
    hashtable_put(m, tstrdup(key), tstrdup(val1));
    void *ret = hashtable_get(m, key);
    ASSERT("[! hashtable_put]: hashtable_put didn't update the value",
           strcmp(val1, ret) == 0);
    hashtable_destroy(m);
    printf(" [hashtable::hashtable_put]: OK\n");
    return 0;
}


/*
 * Tests lookup function of the hashtable
 */
static char *test_hashtable_get(void) {
    HashTable *m = hashtable_new(NULL);
    char *key = "hello";
    char *val = "world";
    hashtable_put(m, tstrdup(key), tstrdup(val));
    char *ret = (char *) hashtable_get(m, key);
    ASSERT("[! hashtable_get]: hashtable_get didn't work as expected",
           strcmp(ret, val) == 0);
    hashtable_destroy(m);
    printf(" [hashtable::hashtable_get]: OK\n");
    return 0;
}


/*
 * Tests the deletion function of the hashtable
 */
static char *test_hashtable_del(void) {
    HashTable *m = hashtable_new(NULL);
    char *key = "hello";
    char *val = "world";
    hashtable_put(m, tstrdup(key), tstrdup(val));
    int status = hashtable_del(m, key);
    ASSERT("[! hashtbale_del]: hashtable size = 1", m->size == 0);
    ASSERT("[! hashtbale_del]: hashtbale_del didn't work as expected",
           status == HASHTABLE_OK);
    hashtable_destroy(m);
    printf(" [hashtable::hashtable_del]: OK\n");
    return 0;
}


static char *test_cluster_add_new_node(void) {

    struct cluster cluster = { 0, 4, list_new(NULL) };

    cluster_add_new_node(&cluster, -1, "127.0.0.1", "8080", false);

    ASSERT("[! cluster_add_new_node]: cluster node not correctly added",
           cluster.size == 1);

    cluster_add_new_node(&cluster, -1, "127.0.0.1", "8081", false);
    cluster_add_new_node(&cluster, -1, "127.0.0.1", "8082", false);
    cluster_add_new_node(&cluster, -1, "127.0.0.1", "8083", false);

    ASSERT("[! cluster_add_new_node]: cluster node not correctly added",
           cluster.size == 4);

    for (struct list_node *ln = cluster.nodes->head; ln; ln = ln->next)
        tfree(ln->data);

    list_destroy(cluster.nodes, 0);

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

    struct cluster cluster = { 0, 4, list_new(NULL) };

    struct cluster_node node1 = {
        false, false, -1, 1000, "127.0.0.1", "8080"
    };
    struct cluster_node node2 = {
        false, false, -1, 1500, "127.0.0.1", "8080"
    };
    struct cluster_node node3 = {
        false, false, -1, 2000, "127.0.0.1", "8080"
    };
    struct cluster_node node4 = {
        false, false, -1, 2500, "127.0.0.1", "8080"
    };

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

    list_destroy(cluster.nodes, 0);
    printf(" [cluster::cluster_get_node]: OK\n");

    return 0;
}


/*
 * All datastructure tests
 */
char *structures_test() {
    RUN_TEST(test_list_push);
    RUN_TEST(test_list_push_back);
    RUN_TEST(test_list_remove_node);
    RUN_TEST(test_trie_create_node);
    RUN_TEST(test_trie_insert);
    RUN_TEST(test_trie_find);
    RUN_TEST(test_trie_delete);
    RUN_TEST(test_trie_prefix_delete);
    RUN_TEST(test_trie_prefix_count);
    RUN_TEST(test_database_prefix_inc);
    RUN_TEST(test_trie_prefix_dec);
    RUN_TEST(test_vector_append);
    RUN_TEST(test_vector_set);
    RUN_TEST(test_vector_get);
    RUN_TEST(test_vector_delete);
    RUN_TEST(test_vector_qsort);
    RUN_TEST(test_hashtable_put);
    RUN_TEST(test_hashtable_get);
    RUN_TEST(test_hashtable_del);
    RUN_TEST(test_cluster_add_new_node);
    RUN_TEST(test_cluster_get_node);

    return 0;
}
