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

#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <malloc.h>
#include "util.h"
#include "config.h"


static size_t memory = 0;

static FILE *fh = NULL;


void t_log_init(const char *file) {
    assert(file);
    fh = fopen(file, "a+");
    if (!fh)
        printf("%lu * WARNING: Unable to open file %s\n",
                (unsigned long) time(NULL), file);
}


void t_log_close(void) {
    if (fh) {
        fflush(fh);
        fclose(fh);
    }
}


void t_log(const uint8_t level, const char *fmt, ...) {

    assert(fmt);

    va_list ap;
    char msg[MAX_LOG_SIZE + 4];

    if (level < config.loglevel) return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Truncate message too long */
    memcpy(msg + MAX_LOG_SIZE, "...", 3);
    msg[MAX_LOG_SIZE + 3] = '\0';

    // Distinguish message level prefix
    const char *mark = "#i*!";

    // Open two handler, one for standard output and a second for the
    // persistent log file
    FILE *fp = stdout;

    if (!fp) return;

    fprintf(fp, "%lu %c %s\n", (unsigned long) time(NULL), mark[level], msg);
    if (fh)
        fprintf(fh, "%lu %c %s\n", (unsigned long) time(NULL), mark[level], msg);

    fflush(fp);
    if (fh)
        fflush(fh);
}

/* auxiliary function to check wether a string is an integer */
bool is_integer(const char *s) {
    const char *k = s;
    for (char c = *k; c != '\0'; c = *(++k))
        if (!isdigit(c))
            return false;
    return true;
}


int parse_int(const char *str) {
    int n = 0;
    const char *s = str;
    while (*s != '\0' && isdigit(*s)) {
        n = (n * 10) + (*s - '0');
        s++;
    }
    return n;
}


void oom(const char *msg) {
    fprintf(stderr, "malloc(3) failed: %s %s\n", strerror(errno), msg);
    fflush(stderr);
    exit(EXIT_FAILURE);
}


void *tmalloc(size_t size) {
    assert(size > 0);
    void *ptr = malloc(size);
    if (ptr)
        memory += size;
    return ptr;
}


void *tcalloc(size_t len, size_t size) {
    assert(len > 0 && size > 0);
    void *ptr = calloc(len, size);
    if (ptr)
        memory += len * size;
    return ptr;
}


void *trealloc(void *ptr, size_t size) {

    assert(size > 0);

    int curr_size = malloc_usable_size(ptr);

    if (!ptr)
        return tmalloc(size);

    if (size == curr_size)
        return ptr;

    void *newptr = realloc(ptr, size);

    memory += (-curr_size) + size;

    return newptr;

}


void tfree(void *ptr) {
    if (!ptr)
        return;
    memory -= malloc_usable_size(ptr);
    free(ptr);
}


size_t memory_used(void) {
    return memory;
}
