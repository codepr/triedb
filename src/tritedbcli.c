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
#include "list.h"
#include "config.h"
#include "server.h"
#include "ringbuf.h"
#include "network.h"
#include "protocol.h"


typedef enum {
    PUT_COMMAND,
    GET_COMMAND,
    DEL_COMMAND,
    TTL_COMMAND,
    INC_COMMAND,
    DEC_COMMAND,
    UNKNOWN_COMMAND
} command_type;


struct kv_command {
    char key[0xff];
    char val[0xff];
    int ttl;
};

struct k_command{
    char key[0xff];
    int ttl;
};


struct cli_command {
    union {
        struct k_command *kc;
        struct kv_command *kvc;
    };
};


struct input_buffer {
    char *buffer;
    size_t buflen;
    size_t inputlen;
} ;


struct input_buffer *input_buffer_create() {
    struct input_buffer *input_buffer = tmalloc(sizeof(*input_buffer));
    input_buffer->buffer = NULL;
    input_buffer->buflen = 0;
    input_buffer->inputlen = 0;

    return input_buffer;
}


static List *split_keys(char *keys) {

    List *list = list_create(NULL);

    char *p = strtok((char *) keys, ",");
    while (p) {
        list_push(list, tstrdup(p));
        p = strtok(NULL, ",");
    }

    return list;
}


void read_line(struct input_buffer *input_buffer) {
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


command_type prepare_command(const struct input_buffer *buffer,
        struct cli_command *command) {

    int args;

    if (STREQ(buffer->buffer, "put", 3)) {
        command->kvc = tmalloc(sizeof(struct kv_command));
        args = sscanf(buffer->buffer, "put %s %s",
                command->kvc->key, command->kvc->val);
        command->kvc->ttl = 0;
        if (args < 2)
            return UNKNOWN_COMMAND;
        return PUT_COMMAND;
    } else if (STREQ(buffer->buffer, "get", 3)) {
        command->kc = tmalloc(sizeof(struct k_command));
        args = sscanf(buffer->buffer, "get %s", command->kc->key);
        if (args < 1)
            return UNKNOWN_COMMAND;
        return GET_COMMAND;
    } else if (STREQ(buffer->buffer, "del", 3)) {
        command->kc = tmalloc(sizeof(struct k_command));
        args = sscanf(buffer->buffer, "del %[^\n]", command->kc->key);
        if (args < 1)
            return UNKNOWN_COMMAND;
        return DEL_COMMAND;
    } else if (STREQ(buffer->buffer, "ttl", 3)) {
        command->kc = tmalloc(sizeof(struct k_command));
        args = sscanf(buffer->buffer, "ttl %s %d",
                command->kc->key, &command->kc->ttl);
        if (args < 2)
            return UNKNOWN_COMMAND;
        return TTL_COMMAND;
    } else if (STREQ(buffer->buffer, "inc", 3)) {
        command->kc = tmalloc(sizeof(struct k_command));
        args = sscanf(buffer->buffer, "inc %[^\n]", command->kc->key);
        if (args < 1)
            return UNKNOWN_COMMAND;
        return INC_COMMAND;
    } else if (STREQ(buffer->buffer, "dec", 3)) {
        command->kc = tmalloc(sizeof(struct k_command));
        args = sscanf(buffer->buffer, "dec %[^\n]", command->kc->key);
        if (args < 1)
            return UNKNOWN_COMMAND;
        return DEC_COMMAND;
    } else
        return UNKNOWN_COMMAND;
}


static ssize_t send_request(int fd, struct request *request, size_t size) {

    struct buffer *buffer = buffer_create(size);

    pack_request(buffer, request, request->command->cmdtype);

    size_t sent;

    if ((sendall(fd, buffer->data, buffer->size, &sent)) < 0)
        perror("send(2): can't write on socket descriptor");

    buffer_release(buffer);

    return sent;
}


static struct response *recv_data(int fd) {

    uint8_t *buf = tmalloc(conf->max_request_size);
    Ringbuffer *rbuffer = ringbuf_create(buf, conf->max_request_size);
    struct packet pkt;
    recv_packet(fd, rbuffer, &pkt);

    struct response *response = unpack_response(pkt.buf);

    ringbuf_release(rbuffer);
    buffer_release(pkt.buf);
    tfree(buf);
    return response;
}


void execute_command(int fd, command_type command, struct cli_command *c) {
    /* Request placeholder */
    struct request *request = NULL;
    struct response *response = NULL;
    List *keylist = NULL;
    ssize_t sent = 0LL;
    switch (command) {
        case PUT_COMMAND:
            request = make_keyval_request((const uint8_t *) c->kvc->key,
                    (const uint8_t *) c->kvc->val, PUT, c->kvc->ttl, F_NOFLAG);
            sent = send_request(fd, request,
                    request->command->kvcommand->header->size);
            printf("%ld bytes sent\n", sent);
            response = recv_data(fd);
            printf("%d bytes received\n", response->ncontent->header->size);
            tfree(c->kvc);
            break;
        case GET_COMMAND:
            request = make_key_request((const uint8_t *) c->kc->key,
                    GET, 0x00, F_NOFLAG);
            sent = send_request(fd, request,
                    request->command->kcommand->header->size);
            printf("%ld bytes sent\n", sent);
            response = recv_data(fd);
            if (response->restype == DATA_CONTENT) {
                printf("%d bytes received\n", response->dcontent->header->size);
                printf("%s\n", response->dcontent->data);
            } else {
                printf("[%d] %d bytes received\n",
                        response->restype, response->ncontent->header->size);
                printf("(nil)\n");
            }
            tfree(c->kc);
            break;
        case INC_COMMAND:
        case DEC_COMMAND:
        case DEL_COMMAND:
            keylist = split_keys(c->kc->key);
            request = make_keylist_request(keylist, command, NULL, F_NOFLAG);
            sent = send_request(fd, request,
                    request->command->kcommand->header->size);
            printf("%ld bytes sent\n", sent);
            response = recv_data(fd);
            printf("%d bytes received\n", response->ncontent->header->size);
            if (response->ncontent->code == 0x00)
                printf("ok\n");
            else
                printf("(nil)\n");
            tfree(c->kc);
            break;
        case TTL_COMMAND:
            request = make_key_request((const uint8_t *) c->kc->key,
                    TTL, c->kc->ttl, F_NOFLAG);
            sent = send_request(fd, request,
                    request->command->kcommand->header->size);
            printf("%ld bytes sent\n", sent);
            response = recv_data(fd);
            printf("%d bytes received\n", response->ncontent->header->size);
            if (response->ncontent->code == 0x00)
                printf("ok\n");
            else
                printf("(nil)\n");
            tfree(c->kc);
            puts("TTL");
            break;
        default:
            puts("ERROR");
            break;
    }
}


int main(int argc, char **argv) {

    struct input_buffer *input_buffer = input_buffer_create();

    struct cli_command *c = tmalloc(sizeof(*c));

    config_set_default();

    // Connect to the listening peer node
    int fd = open_connection("127.0.0.1", 9090);

    if (fd < 0)
        return -1;

    while (1) {

        printf("tritedb@127.0.0.1> ");

        read_line(input_buffer);

        command_type command = prepare_command(input_buffer, c);

        execute_command(fd, command, c);
    }

    return 0;
}
