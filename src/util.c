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


void t_log(uint8_t level, const char *fmt, ...) {

    assert(fmt);

    va_list ap;
    char msg[MAX_LOG_SIZE + 4];

    if (level < conf->loglevel)
        return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Truncate message too long and copy 3 bytes to make space for 3 dots */
    memcpy(msg + MAX_LOG_SIZE, "...", 3);
    msg[MAX_LOG_SIZE + 3] = '\0';

    // Distinguish message level prefix
    const char *mark = "#i*!";

    // Open two handler, one for standard output and a second for the
    // persistent log file
    FILE *fp = stdout;

    if (!fp)
        return;

    fprintf(fp, "%lu %c %s\n", (unsigned long) time(NULL), mark[level], msg);
    if (fh)
        fprintf(fh, "%lu %c %s\n", (unsigned long) time(NULL), mark[level], msg);

    fflush(fp);
    if (fh)
        fflush(fh);
}

/* Auxiliary function to check wether a string is an integer */
bool is_integer(const char *string) {
    for (; *string; ++string)
        if (!isdigit(*string))
            return false;
    return true;
}

/* Parse the integer part of a string, by effectively iterate through it and
   converting the numbers found */
int parse_int(const char *string) {
    int n = 0;

    while (*string && isdigit(*string)) {
        n = (n * 10) + (*string - '0');
        string++;
    }
    return n;
}

/* Return the 'length' of a positive number, as the number of chars it would
 * take in a string */
int number_len(size_t number) {
    int len = 1;
    while (number) {
        len++;
        number /= 10;
    }
    return len;
}

/* Out of memory print, for now it just output on stderr and exit */
void oom(const char *msg) {
    fprintf(stderr, "malloc(3) failed: %s %s\n", strerror(errno), msg);
    fflush(stderr);
    exit(EXIT_FAILURE);
}

/* Custom malloc function, allocate a defined size of bytes plus 8, the size
   of an unsigned long long, and append the length choosen at the beginning of
   the memory chunk as an unsigned long long, returning the memory chunk
   allocated just 8 bytes after the start; this way it is possible to track
   the memory usage at every allocation */
void *tmalloc(size_t size) {

    assert(size > 0);

    void *ptr = malloc(size + sizeof(size_t));

    if (!ptr)
        return NULL;

    memory += size + sizeof(size_t);

    *((size_t *) ptr) = size;

    return (char *) ptr + sizeof(size_t);
}

/* Same as tmalloc, but with calloc, creating chunk o zero'ed memory.
   TODO: still a suboptimal solution */
void *tcalloc(size_t len, size_t size) {

    assert(len > 0 && size > 0);

    void *ptr = calloc(len, size + sizeof(size_t));

    if (!ptr)
        return NULL;

    *((size_t *) ptr) = size;

    memory += len * (size + sizeof(size_t));

    return (char *) ptr + sizeof(size_t);
}

/* Same of tmalloc but with realloc, resize a chunk of memory pointed by a
   given pointer, again appends the new size in front of the byte array */
void *trealloc(void *ptr, size_t size) {

    assert(size > 0);

    if (!ptr)
        return tmalloc(size);

    void *realptr = (char *)ptr-sizeof(size_t);

    size_t curr_size = *((size_t *) realptr);

    if (size == curr_size)
        return ptr;

    void *newptr = realloc(realptr, size + sizeof(size_t));

    if (!newptr)
        return NULL;

    *((size_t *) newptr) = size;

    memory += (-curr_size) + size + sizeof(size_t);

    return (char *) newptr + sizeof(size_t);

}

/* Custom free function, must be used on memory chunks allocated with t*
   functions, it move the pointer 8 position backward by the starting address
   of memory pointed by `ptr`, this way it knows how many bytes will be
   free'ed by the call */
void tfree(void *ptr) {

    if (!ptr)
        return;

    void *realptr = (char *) ptr - sizeof(size_t);

    if (!realptr)
        return;

    size_t ptr_size = *((size_t *) realptr);

    if (memory - ptr_size + sizeof(size_t) < 0)
        memory = 0;
    else
        memory -= ptr_size + sizeof(size_t);

    free(realptr);
}

/* Retrieve the bytes allocated by t* functions by backwarding the pointer of
   8 positions, the size of an unsigned long long in order to read the number
   of allcated bytes */
size_t malloc_size(void *ptr) {

    if (!ptr)
        return 0L;

    void *realptr = (char *) ptr - sizeof(size_t);

    if (!realptr)
        return 0L;

    size_t ptr_size = *((size_t *) realptr);

    return ptr_size;
}

/* As strdup but using tmalloc instead of malloc, to track the number of bytes
   allocated and to enable use of tfree on duplicated strings without having to
   care when to use a normal free or a tfree */
char *tstrdup(const char *s) {

    char *ds = tmalloc(strlen(s) + 1);

    if (!ds)
        return NULL;

    // TODO: Bugged, change to snprintf
    strcpy(ds, s);

    return ds;
}


size_t memory_used(void) {
    return memory;
}
