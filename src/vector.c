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
#include "util.h"
#include "vector.h"


Vector *vector_create(void) {

    Vector *v = tmalloc(sizeof(*v));

    v->maxsize = vector_create_CAPACITY;
    v->size = 0L;
    v->items = tmalloc(v->maxsize * sizeof(void *));

    for (int i = 0; i < v->maxsize; i++)
        v->items[i] = NULL;

    return v;
}


void vector_release(Vector *v) {
    tfree(v->items);
    tfree(v);
}


size_t vector_size(const Vector *v) {
    return v->size;
}


static void vector_resize(Vector *v, int newsize) {

    void **items = trealloc(v->items, sizeof(void *) * newsize);

    if (items) {
        v->items = items;
        v->maxsize = newsize;
    }
}


void vector_append(Vector *v, void *item) {
    if (v->maxsize == v->size)
        vector_resize(v, v->maxsize * 2);
    v->items[v->size++] = item;
}


void vector_set(Vector *v, int index, void *item) {
    if (index >= 0 && index < v->size)
        v->items[index] = item;
}


void *vector_get(const Vector *v, int index) {
    if (index >= 0 && index < v->size)
        return v->items[index];
    return NULL;
}


void vector_delete(Vector *v, int index) {

    if (index < 0 || index >= v->size)
        return;

    v->items[index] = NULL;

    for (int i = index; i < v->size - 1; i++) {
        v->items[i] = v->items[i + 1];
        v->items[i + 1] = NULL;
    }

    v->size--;

    if (v->size > 0 && v->size == v->maxsize / 4)
        vector_resize(v, v->maxsize / 2);
}


static void swap(void *a, void *b, size_t len) {

    uint8_t *p = a, *q = b, tmp;

    for (size_t i = 0; i != len; ++i) {
        tmp = p[i];
        p[i] = q[i];
        q[i] = tmp;
    }
}


static void quicksort(Vector *v, int left, int right,
                      qsort_func cmp_func, size_t ptrlen) {

    if (!v || left >= right)
        return;

    void *pivot = vector_get(v, right);

    int count = left;

    for (int i = left; i <= right; i++) {

        if (cmp_func(vector_get(v, i), pivot) == true) {

            swap(vector_get(v, count), vector_get(v, i), ptrlen);

            count++;
        }
    }

    quicksort(v, left, count - 2, cmp_func, ptrlen);
    quicksort(v, count, right, cmp_func, ptrlen);
}


void vector_qsort(Vector *v, qsort_func cmp_func, size_t ptrlen) {
    if (!v || v->size < 2)
        return;
    quicksort(v, 0, v->size - 1, cmp_func, ptrlen);
}
