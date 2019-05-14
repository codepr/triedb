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
#include "server.h"
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

    return key % RING_SIZE;
}


static int compare_upper_bound(void *arg1, void *arg2) {

    /* cast to cluster_node */
    uint16_t n1 = ((struct cluster_node *) arg1)->upper_bound;
    uint16_t n2 = ((struct cluster_node *) arg2)->upper_bound;

    if (n1 == n2)
        return 0;

    return n1 < n2 ? -1 : 1;
}


static void insert_node(struct cluster *cluster,
                        struct cluster_node *cnode, bool vnode) {

    cnode->vnode = vnode;

    /*
     * Push the new node into the cluster node list and sort it by the
     * upper_bound value of each node
     */
    list_push(cluster->nodes, cnode);

    /*
     * O(n), can be improved by inserting in an almost sorted list but for now
     * this is OK
     */
    cluster->nodes->head = list_merge_sort(cluster->nodes->head,
                                           compare_upper_bound);

    if (!vnode)
        cluster->size++;
}

/*
 * To create our consitent hash ring for now we just distribute randomly around
 * the circle our nodes by getting a random value in range [0, RING_SIZE),
 * obtained by generating a hash with CRC32 of the node address:
 *
 *      uint16_t hash = CRC32(host + port) % RING_SIZE.
 *
 * Further development will make sure that nodes will be distributed more
 * evenly around by using virtual nodes, in other words by replicating each
 * node multiple times around the circle.
 */
int cluster_add_new_node(struct cluster *cluster, struct client *client,
                         const char *addr, const char *port, bool self) {

    char fulladdr[30];

    /*
     * First we insert the real node into the hash ring, positioned by
     * computing HASH(addr + port) % RING_SIZE
     */
    strcpy(fulladdr, addr);

    // Get a ring point by hashing the node address + port
    uint16_t upper_bound = hash(strcat(fulladdr, port)) % RING_SIZE;

    struct cluster_node *cnode = tmalloc(sizeof(*cnode));
    if (!cnode)
        return -1;

    cnode->self = self;
    strcpy((char *) cnode->host, addr);
    strcpy((char *) cnode->port, port);
    cnode->upper_bound = upper_bound;
    cnode->link = client;

    /* Set to false the vnode flag: The first is the real node */
    insert_node(cluster, cnode, false);

    int replicas = cluster->replicas;

    /*
     * Cycle replicas times or the number of virtual nodes that will be added
     * to the hash ring
     */
    while (replicas--) {

        /*
         * Create prefix number to be append to the full address in order to
         * distributed more evenly the nodes into the ring by creating virtual
         * nodes
         */
        char prefix[20];

        sprintf(prefix, "%d", replicas);

        char fulladdr[30];

        /*
         * Here we got:
         * 1127.0.0.1, 2127.0.0.1 etc
         */
        strcpy(fulladdr, strcat(prefix, addr));

        // Get a ring point by hashing the vnode
        uint16_t upper_bound = hash(strcat(fulladdr, port)) % RING_SIZE;

        struct cluster_node *vnode = tmalloc(sizeof(*vnode));
        if (!vnode)
            return -1;

        vnode->self = self;
        strcpy((char *) vnode->host, addr);
        strcpy((char *) vnode->port, port);
        vnode->upper_bound = upper_bound;
        vnode->link = client;

        /*
         * Now we set to true the vnode flag indicating that this node is
         * effectively a virtual node, in other word a replica of an already
         * existing node in the ring
         */
        insert_node(cluster, vnode, true);

    }

    return 0;
}

/*
 * Retrieve the cluster node which a given hash belong to, the hash is
 * obtained by doing CRC32(key) % RING_SIZE and represents a point in
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


size_t cluster_size(struct cluster *cluster) {
    return cluster->nodes->len;
}


void log_cluster_ring(struct cluster *cluster) {

    struct list_node *head = cluster->nodes->head;
    for (struct list_node *cur = head; cur; cur = cur->next) {

        struct cluster_node *cnode = cur->data;

        tdebug("%s %s -> %s %s",
               cnode->vnode ? "vnode" : "node",
               cnode->link->uuid,
               cnode->upper_bound,
               cnode->self ? "(self)" : "");
    }
}
