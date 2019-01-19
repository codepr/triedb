/* BSD 2-Clause License
 *
 * Copyright (c) 2018, Andrea Giacomo Baldan All rights reserved.
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

#include "util.h"
#include "list.h"
#include "cluster.h"
#include "hashtable.h"
#include <stdlib.h>
#include <string.h>


/* Borrowed from hashtable.c, TODO refactor */
uint16_t hash(const char *keystr) {

    if (!keystr)
        return -1;

    uint64_t key = crc32((const uint8_t *) keystr, strlen(keystr));

    /* Robert Jenkins' 32 bit Mix Function */
    key += (key << 12);
    key ^= (key >> 22);
    key += (key << 4);
    key ^= (key >> 9);
    key += (key << 10);
    key ^= (key >> 2);
    key += (key << 7);
    key ^= (key >> 12);

    /* Knuth's Multiplicative Method */
    key = (key >> 3) * KPRIME;

    return key % RING_POINTS;
}


static int compare_upper_bound(void *arg1, void *arg2) {

    /* cast to cluster_node */
    uint16_t n1 = ((struct cluster_node *) arg1)->upper_bound;
    uint16_t n2 = ((struct cluster_node *) arg2)->upper_bound;

    if (n1 == n2)
        return 0;

    return n1 < n2 ? -1 : 1;
}

/*
 * To create our consitent hash ring for now we just distribute randomly around
 * the circle our nodes by getting a random value in range [0, RING_POINTS),
 * obtained by generating a hash with CRC32 of the node address:
 *
 *      uint16_t hash = CRC32(host + port) % RING_POINTS.
 *
 * Further development will make sure that nodes will be distributed more
 * evenly around by using virtual nodes, in other words by replicating each
 * node multiple times around the circle.
 */
int cluster_add_new_node(struct cluster *cluster,
        struct client *client, const char *addr, bool self) {

    // Get a ring point
    uint16_t upper_bound = hash(addr) % RING_POINTS;

    struct cluster_node *new_node = tmalloc(sizeof(*new_node));
    if (!new_node)
        return -1;

    new_node->self = self;
    new_node->upper_bound = upper_bound;
    new_node->link = client;

    /*
     * Push the new node into the cluster node list and sort it by the
     * upper_bound value of each node
     */
    list_push(cluster->nodes, new_node);

    /*
     * O(n), can be improved by inserting in an almost sorted list but for now
     * this is OK
     */
    cluster->nodes->head =
        list_merge_sort(cluster->nodes->head, compare_upper_bound);

    return 0;
}

/*
 * Retrieve the cluster node which a given hash belong to, the hash is
 * obtained by doing CRC32(key) % RING_POINTS and represents a point in
 * the consistent hash ring
 */
struct cluster_node *cluster_get_node(struct cluster *cluster,
        uint16_t hash_value) {

    /*
     * Edge case, a list with a single node (very unlikely) should just return
     * the node itself
     */
    if (cluster->nodes->len == 1)
        return cluster->nodes->head->data;

    struct list_node *cur = cluster->nodes->head;

    /*
     * Move one the cursor until we find that the next node have an upper_bound
     * >= to hash_value or until we reach the end of the list
     */
    while (cur->next &&
            ((struct cluster_node *) cur->next->data)->upper_bound < hash_value)
        cur = cur->next;

    /*
     * Edge case, we reached the end of the circle and the hash_value is past
     * the last cluster_node upper_bound, so we are in the first node again
     */
    if (!cur->next &&
            ((struct cluster_node *) cur->data)->upper_bound < hash_value)
        return cluster->nodes->head->data;

    uint16_t upper_bound = ((struct cluster_node *) cur->data)->upper_bound;

    return hash_value > upper_bound ? cur->next->data : cur->data;
}

/* Add an already created and assigned node to the circle */
void cluster_add_node(struct cluster *cluster, struct cluster_node *node) {

    list_push(cluster->nodes, node);

    cluster->nodes->head =
        list_merge_sort(cluster->nodes->head, compare_upper_bound);
}
