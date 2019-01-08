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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"


typedef enum {
    PUT_COMMAND,
    GET_COMMAND,
    DEL_COMMAND,
    TTL_COMMAND,
    UNKNOWN_COMMAND
} CommandType;


typedef struct {
    char key[0xff];
    char val[0xff];
    int ttl;
} KeyValCommand;

typedef struct {
    char key[0xff];
    int ttl;
} KeyCommand;


typedef struct {
    union {
        KeyCommand *kc;
        KeyValCommand *kvc;
    };
} Command;


typedef struct {
    char *buffer;
    size_t buflen;
    size_t inputlen;
} InputBuffer;


InputBuffer *input_buffer_new() {
    InputBuffer *input_buffer = tmalloc(sizeof(InputBuffer));
    input_buffer->buffer = NULL;
    input_buffer->buflen = 0;
    input_buffer->inputlen = 0;

    return input_buffer;
}


void read_line(InputBuffer *input_buffer) {
    size_t bytes_read =
        getline(&(input_buffer->buffer), &(input_buffer->buflen), stdin);

    if (bytes_read <= 0) {
        printf("Error reading input\n");
        exit(EXIT_FAILURE);
    }

    // Ignore trailing newline
    input_buffer->inputlen = bytes_read - 1;
    input_buffer->buffer[bytes_read - 1] = 0;
}


CommandType prepare_command(const InputBuffer *buffer, Command *command) {

    int args;

    if (STREQ(buffer->buffer, "put", 3)) {
        command->kvc = tmalloc(sizeof(KeyValCommand));
        args = sscanf(buffer->buffer, "put %s %s", command->kvc->key, command->kvc->val);
        if (args < 2)
            return UNKNOWN_COMMAND;
        return PUT_COMMAND;
    } else if (STREQ(buffer->buffer, "get", 3)) {
        command->kc = tmalloc(sizeof(KeyCommand));
        args = sscanf(buffer->buffer, "get %s", command->kc->key);
        if (args < 1)
            return UNKNOWN_COMMAND;
        return GET_COMMAND;
    } else if (STREQ(buffer->buffer, "del", 3)) {
        command->kc = tmalloc(sizeof(KeyCommand));
        args = sscanf(buffer->buffer, "del %s", command->kc->key);
        if (args < 1)
            return UNKNOWN_COMMAND;
        return DEL_COMMAND;
    } else if (STREQ(buffer->buffer, "ttl", 3)) {
        command->kc = tmalloc(sizeof(KeyCommand));
        args = sscanf(buffer->buffer, "ttl %s", command->kc->key);
        if (args < 1)
            return UNKNOWN_COMMAND;
        return TTL_COMMAND;
    } else
        return UNKNOWN_COMMAND;
}


void execute_command(CommandType command, Command *c) {
    switch (command) {
        case PUT_COMMAND:
            tfree(c->kvc);
            puts("PUT");
            break;
        case GET_COMMAND:
            tfree(c->kc);
            puts("GET");
            break;
        case DEL_COMMAND:
            tfree(c->kc);
            puts("DEL");
            break;
        case TTL_COMMAND:
            tfree(c->kc);
            puts("TTL");
            break;
        default:
            puts("ERROR");
            break;
    }
}


int main(int argc, char **argv) {

    InputBuffer *input_buffer = input_buffer_new();

    Command *c = tmalloc(sizeof(Command));

    while (1) {

        printf("> ");

        read_line(input_buffer);

        CommandType command = prepare_command(input_buffer, c);

        execute_command(command, c);
    }

    return 0;
}
