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
#include "list.h"
#include "util.h"
#include "server.h"


static ListNode *list_node_remove(ListNode *, ListNode *, compare_func, int *);

/*
 * Create a list, initializing all fields
 */
List *list_init(void) {

    List *l = tmalloc(sizeof(List));

    if (!l) {
        perror("malloc(3) failed");
        exit(EXIT_FAILURE);
    }

    // set default values to the List structure fields
    l->head = l->tail = NULL;
    l->len = 0L;

    return l;
}


/*
 * Destroy a list, releasing all allocated memory
 */
void list_free(List *l, int deep) {

    if (!l) return;

    ListNode *h = l->head;
    ListNode *tmp;

    // free all nodes
    while (l->len--) {

        tmp = h->next;

        if (h) {
            if (h->data && deep == 1) tfree(h->data);
            tfree(h);
        }

        h = tmp;
    }

    // free List structure pointer
    tfree(l);
}

/*
 * Destroy a list, releasing all allocated memory but the list itself
 */
void list_clear(List *l, int deep) {

    if (!l) return;

    ListNode *h = l->head;
    ListNode *tmp;

    // free all nodes
    while (l->len--) {

        tmp = h->next;

        if (h) {
            if (h->data && deep == 1) tfree(h->data);
            tfree(h);
        }

        h = tmp;
    }

    l->head = l->tail = NULL;
    l->len = 0L;
}

/*
 * Attach a node to the head of a new list
 */
List *list_attach(List *l, ListNode *head, unsigned long len) {
    // set default values to the List structure fields
    l->head = head;
    l->len = len;
    return l;
}

/*
 * Insert value at the front of the list
 * Complexity: O(1)
 */
List *list_push(List *l, void *val) {

    ListNode *new_node = tmalloc(sizeof(ListNode));

    if (!new_node) {
        perror("malloc(3) failed");
        exit(EXIT_FAILURE);
    }

    new_node->data = val;

    if (l->len == 0) {
        l->head = l->tail = new_node;
        new_node->next = NULL;
    } else {
        new_node->next = l->head;
        l->head = new_node;
    }

    l->len++;

    return l;
}


/*
 * Insert value at the back of the list
 * Complexity: O(1)
 */
List *list_push_back(List *l, void *val) {

    ListNode *new_node = tmalloc(sizeof(ListNode));

    if (!new_node) {
        perror("malloc(3) failed");
        exit(EXIT_FAILURE);
    }

    new_node->data = val;
    new_node->next = NULL;

    if (l->len == 0) {
        l->head = l->tail = new_node;
    } else {
        l->tail->next = new_node;
        l->tail = new_node;
    }

    l->len++;

    return l;
}


void list_remove(List *l, ListNode *node, compare_func cmp) {

    if (!l || !node)
        return;

    int counter = 0;

    l->head = list_node_remove(l->head, node, cmp, &counter);

    l->len -= counter;

}


static ListNode *list_node_remove(ListNode *head,
        ListNode *node, compare_func cmp, int *counter) {

    if (!head)
        return NULL;

    if (cmp(head, node) == 0) {

        ListNode *tmp_next = head->next;
        tfree(head);
        head = NULL;

        // Update remove counter
        (*counter)++;

        return tmp_next;
    }

    head->next = list_node_remove(head->next, node, cmp, counter);

    return head;
}


static ListNode *list_remove_single_node(ListNode *head,
        void *data, ListNode **ret, compare_func cmp) {

    if (!head)
        return NULL;

    // We want the first match
    if (cmp(head, data) == 0 && !*ret) {

        ListNode *tmp_next = head->next;

        *ret = head;

        return tmp_next;

    }

    head->next = list_remove_single_node(head->next, data, ret, cmp);

    return head;

}


ListNode *list_remove_node(List *list, void *data, compare_func cmp){

    if (list->len == 0 || !list)
        return NULL;

    ListNode *node = NULL;

    list_remove_single_node(list->head, data, &node, cmp);

    if (node) {
        list->len--;
        node->next = NULL;
    }

    return node;
}

/*
 * Returns a pointer to a node near the middle of the list,
 * after having truncated the original list before that point.
 */
static ListNode *bisect_list(ListNode *head) {
    /* The fast pointer moves twice as fast as the slow pointer. */
    /* The prev pointer points to the node preceding the slow pointer. */
    ListNode *fast = head, *slow = head, *prev = NULL;

    while (fast != NULL && fast->next != NULL) {
        fast = fast->next->next;
        prev = slow;
        slow = slow->next;
    }

    if (prev != NULL)
        prev->next = NULL;

    return slow;
}

/*
 * Merges two list by using the head node of the two, sorting them according to
 * lexigraphical ordering of the node names.
 */
static ListNode *merge_list(ListNode *list1, ListNode *list2) {

    ListNode dummy_head = { NULL, NULL }, *tail = &dummy_head;

    unsigned long long now = time(NULL);
    unsigned long long delta_l1, delta_l2;

    while (list1 && list2) {

        /* cast to cluster_node */
        struct NodeData *n1 = ((struct ExpiringKey *) list1->data)->nd;
        struct NodeData *n2 = ((struct ExpiringKey *) list2->data)->nd;

        delta_l1 = (n1->ctime + n1->ttl) - now;
        delta_l2 = (n2->ctime + n2->ttl) - now;

        ListNode **min = delta_l1 <= delta_l2 ? &list1 : &list2;
        ListNode *next = (*min)->next;
        tail = tail->next = *min;
        *min = next;
    }

    tail->next = list1 ? list1 : list2;
    return dummy_head.next;
}

/*
 * Merge sort for nodes list, based on the name field of every node
 */
ListNode *merge_sort(ListNode *head) {

    ListNode *list1 = head;

    if (!list1 || !list1->next)
        return list1;

    /* find the middle */
    ListNode *list2 = bisect_list(list1);

    return merge_list(merge_sort(list1), merge_sort(list2));
}

/* Search for a given node based on a comparison of char stored in structure
 * and a value, O(n) at worst
 */
ListNode *linear_search(List *list, int value) {

    if (!list || list->len == 0)
        return NULL;

    for (ListNode *cur = list->head; cur != NULL; cur = cur->next) {
        if (((TrieNode *) cur->data)->chr == value)
            return cur;
        else if (((TrieNode *) cur->data)->chr > value)
            break;
    }

    return NULL;
}


static ListNode *merge_tnode_list(ListNode *list1, ListNode *list2) {

    ListNode dummy_head = { NULL, NULL }, *tail = &dummy_head;

    while (list1 && list2) {

        /* cast to cluster_node */
        char chr1 = ((TrieNode *) list1->data)->chr;
        char chr2 = ((TrieNode *) list2->data)->chr;

        ListNode **min = chr1 <= chr2 ? &list1 : &list2;
        ListNode *next = (*min)->next;
        tail = tail->next = *min;
        *min = next;
    }

    tail->next = list1 ? list1 : list2;
    return dummy_head.next;
}


ListNode *merge_sort_tnode(ListNode *head) {

    ListNode *list1 = head;

    if (!list1 || !list1->next)
        return list1;

    /* find the middle */
    ListNode *list2 = bisect_list(list1);

    return merge_tnode_list(merge_sort_tnode(list1), merge_sort_tnode(list2));
}
