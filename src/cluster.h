/* BSD 2-Clause License
 *
 * Copyright (c) 2018, 2019 Andrea Giacomo Baldan All rights reserved.
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

#ifndef CLUSTER_H
#define CLUSTER_H

#include "list.h"
#include <arpa/inet.h>

#define RING_SIZE 4096

#define KPRIME 2654435761

/*
 * Contains the max index in the ring size handled by the node and a link to
 * the client referring to the node
 */
struct cluster_node {
    bool self;
    bool vnode;
    int fd;
    uint16_t upper_bound;
    const char host[INET_ADDRSTRLEN + 1];
    const char port[6];
};

/* Just a list of nodes for now */
struct cluster {
    int size;
    int replicas;
    List *nodes;
};

/* Compute a hash of a string by using CRC32 function mod RING_SIZE */
uint16_t hash(const char *);

/*
 * Add new node into the cluster, create a new node to be inserted into the
 * list at the right index
 */
int cluster_add_new_node(struct cluster *, int,
                         const char *, const char *, bool);

/*
 * Retrieve a cluster node based on the index, cluster node list is sorted by
 * upper_bound limit of each node
 */
struct cluster_node *cluster_get_node(struct cluster *, uint16_t);

/* Return the size of the hash ring */
size_t cluster_size(struct cluster *);

/* Utility function, log the hashring distribution of virtual node */
void log_cluster_ring(struct cluster *);


#endif
