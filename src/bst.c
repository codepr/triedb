/*
 * BSD 2-Clause License
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

#include "bst.h"


#define MAX(a, b) a > b ? a : b
#define HEIGHT(n) !n ? 0 : n->height
#define BALANCE(n) !n ? 0 : (HEIGHT(n->left)) - (HEIGHT(n->right))


struct bst_node *bst_new(unsigned char key, const void *data) {
    struct bst_node *node = tmalloc(sizeof(*node));
    node->key = key;
    node->height = 1;
    node->left = NULL;
    node->right = NULL;
    node->data = (void *) data;
    return node;
}


static struct bst_node *bst_rotate_right(struct bst_node *y) {
    struct bst_node *x = y->left;
    struct bst_node *t2 = x->right;

    x->right = y;
    y->left = t2;

    y->height = MAX(HEIGHT(y->left), HEIGHT(y->right)) + 1;
    x->height = MAX(HEIGHT(x->left), HEIGHT(x->right)) + 1;

    return x;
}


static struct bst_node *bst_rotate_left(struct bst_node *x) {
    struct bst_node *y = x->left;
    struct bst_node *t2 = y->right;

    y->right = x;
    x->left = t2;

    x->height = MAX(HEIGHT(x->left), HEIGHT(x->right)) + 1;
    y->height = MAX(HEIGHT(y->left), HEIGHT(y->right)) + 1;

    return y;
}


static struct bst_node *bst_min(const struct bst_node *node) {
    const struct bst_node *curr = node;
    while (curr->left)
        curr = curr->left;
    return (struct bst_node *) curr;
}

struct bst_node *bst_insert(struct bst_node *node,
                            unsigned char key, const void *data) {
    if (!node)
        return bst_new(key, data);
    if (key < node->key)
        node->left = bst_insert(node->left,key,data);
    else if (key > node->key)
        node->right = bst_insert(node->right, key, data);
    else
        return node;

    node->height = 1 + MAX((HEIGHT(node->left)), (HEIGHT(node->right)));

    int balance = BALANCE(node);

    if (balance > 1 && key < node->left->key)
        return bst_rotate_right(node);
    if (balance < -1 && key > node->right->key)
        return bst_rotate_left(node);

    if (balance > 1 && key > node->left->key) {
        node->left = bst_rotate_left(node->left);
        return bst_rotate_right(node);
    }

    if (balance < -1 && key < node->right->key) {
        node->right = bst_rotate_right(node->right);
        return bst_rotate_left(node);
    }

    return node;
}


struct bst_node *bst_search(const struct bst_node *node, unsigned char key) {
    if (!node)
        return NULL;
    if (key == node->key)
        return (struct bst_node *) node;
    if (key < node->key)
        return bst_search(node->left, key);
    else
        return bst_search(node->right, key);
}


struct bst_node *bst_delete(struct bst_node *node, unsigned char key) {
    if (!node)
        return node;
    if (key < node->key)
        node->left = bst_delete(node->left, key);
    if (key > node->key)
        node->right = bst_delete(node->right, key);
    else {
        if (!node->left || !node->right) {
            struct bst_node *tmp = node->left ? node->left : node->right;
            if (!tmp) {
                tmp = node;
                node = NULL;
            } else
                *node = *tmp;
            tfree(tmp);
        } else {
            struct bst_node *tmp = bst_min(node->right);
            node->key = tmp->key;
            node->right = bst_delete(node->right, tmp->key);
        }
    }

    // If the tree had only one node then return
    if (!node)
      return node;

    // STEP 2: UPDATE HEIGHT OF THE CURRENT NODE
    node->height = 1 + MAX((HEIGHT(node->left)), (HEIGHT(node->right)));

    // STEP 3: GET THE BALANCE FACTOR OF THIS NODE (to
    // check whether this node became unbalanced)
    int balance = BALANCE(node);

    // If this node becomes unbalanced, then there are 4 cases

    // Left Left Case
    if (balance > 1 && BALANCE(node->left) >= 0)
        return bst_rotate_right(node);

    // Left Right Case
    if (balance > 1 && BALANCE(node->left) < 0) {
        node->left =  bst_rotate_left(node->left);
        return bst_rotate_right(node);
    }

    // Right Right Case
    if (balance < -1 && BALANCE(node->right) <= 0)
        return bst_rotate_left(node);

    // Right Left Case
    if (balance < -1 && BALANCE(node->right) > 0) {
        node->right = bst_rotate_right(node->right);
        return bst_rotate_left(node);
    }

    return node;
}
