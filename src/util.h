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

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>


#define MAX_LOG_SIZE 99


enum { DEBUG, INFO, WARNING, ERROR };


void oom(const char *);
bool is_integer(const char *);
int parse_int(const char *);

/* Logging */
void t_log_init(const char *);
void t_log_close(void);
void t_log(const uint8_t, const char *, ...);

/* Memory management */
void *tmalloc(size_t);
void *tcalloc(size_t, size_t);
void *trealloc(void *, size_t);
size_t malloc_size(void *);
void tfree(void *);
char *tstrdup(const char *);

size_t memory_used(void);


#define log(...) t_log( __VA_ARGS__ )
#define tdebug(...) log(DEBUG, __VA_ARGS__)
#define twarning(...) log(WARNING, __VA_ARGS__)
#define terror(...) log(ERROR, __VA_ARGS__)
#define tinfo(...) log(INFO, __VA_ARGS__)


#endif
